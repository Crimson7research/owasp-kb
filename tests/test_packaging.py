"""Validate packaging manifests and skill frontmatter."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

MARKETPLACE = Path(".claude-plugin/marketplace.json")
PLUGIN = Path("plugins/owasp-kb/.claude-plugin/plugin.json")
MCP_CONFIG = Path("plugins/owasp-kb/.mcp.json")
SKILLS_DIR = Path("plugins/owasp-kb/skills")

EXPECTED_SKILLS = {
    "owasp-secure-coding",
    "owasp-asvs-verify",
    "owasp-asvs-gap-report",
    "owasp-threat-model",
}
# The two skills that fan out over ~140 subagents for hours. The other two run in one
# session in minutes, where a nine-stage ledger over five steps is overhead.
FAN_OUT_SKILLS = {"owasp-asvs-verify", "owasp-asvs-gap-report"}

STAGES = [
    "Agree scope",
    "Record exclusions",
    "Build inventory",
    "Triage applicability",
    "Refute exemptions",
    "Assess chapters",
    "Verify findings",
    "Assemble roster",
    "Write report",
]
TOOL_NAMES = {
    "kb_info",
    "owasp_search",
    "owasp_outline",
    "owasp_get",
    "owasp_checklist",
    "owasp_related",
    "owasp_roster",
    "cwe_get",
    "cwe_search",
    "cwe_related",
}


def test_marketplace_is_valid_json_with_required_fields():
    data = json.loads(MARKETPLACE.read_text())
    assert data["name"] == "owasp-kb"
    assert data["owner"]["name"]
    assert len(data["plugins"]) == 1


def test_marketplace_points_at_the_plugin_directory():
    plugin = json.loads(MARKETPLACE.read_text())["plugins"][0]
    assert plugin["name"] == "owasp-kb"
    assert plugin["source"] == "./plugins/owasp-kb"
    assert Path(plugin["source"]).is_dir()
    assert plugin["description"]


def test_plugin_manifest_is_valid():
    data = json.loads(PLUGIN.read_text())
    assert data["name"] == "owasp-kb"
    assert data["description"]
    assert data["license"] == "MIT"


def test_plugin_declares_its_mcp_config():
    """Installing the plugin must also wire up the server; otherwise the skills
    reference tools that do not exist."""
    data = json.loads(PLUGIN.read_text())
    assert data["mcpServers"] == "./.mcp.json"
    assert MCP_CONFIG.exists()


def test_no_plugin_version_field_is_declared():
    """The plugin cache is keyed on the resolved version, and Claude Code resolves
    that to the commit SHA when `version` is absent -- "Bump the field on every
    release, or omit it to use the commit SHA." Omitting it makes every commit a
    distinct version by construction; observed directly, a marker commit moved an
    install from cache key 37b3cef5e478 to 5fbc08c9a745.

    That is what let scripts/plugin_digest.py and
    plugins/owasp-kb/.claude-plugin/content.sha256 be deleted rather than merely
    relocated: they existed only to catch a plugin content change shipped without
    a bump, which cannot happen when the version *is* the content's commit.

    Re-adding the field silently reinstates that hazard, and it is quiet in an
    expensive way -- `/plugin` reports "already at the latest version", `/mcp`
    reports a successful reconnect and `/reload-plugins` reloads the old files,
    three green statuses every one of them true about the wrong copy. Recovery
    needs a manual uninstall and reinstall, and nothing says so. It cost exactly
    that once.
    """
    plugin = json.loads(PLUGIN.read_text())
    assert "version" not in plugin, (
        "plugin.json declares a version again, so the cache stops tracking "
        "commits. Either drop the field, or restore scripts/plugin_digest.py and "
        "the guard it enforced -- do not leave the field with no guard"
    )
    entry = json.loads(MARKETPLACE.read_text())["plugins"][0]
    assert "version" not in entry, (
        "the marketplace entry pins a version for the plugin, which overrides "
        "commit-SHA resolution the same way plugin.json's field does"
    )


def _server_command() -> str:
    """The single shell command that starts the server."""
    server = json.loads(MCP_CONFIG.read_text())["mcpServers"]["owasp-kb"]
    assert server["command"] == "sh", "the command must be one a bare PATH always resolves"
    return " ".join(server["args"])


def test_the_server_command_needs_no_path_lookup_or_variable_expansion():
    """A wrapper on the plugin's bin/ failed with ENOENT: that directory is on
    PATH for shell tools, and the MCP subprocess does not inherit it. ${...}
    expansion inside .mcp.json is equally unverified -- no installed plugin
    relies on it, and it would fail silently rather than loudly.

    sh is resolvable anywhere, and the shell does the expansion itself."""
    args = _server_command()
    assert "-c" in json.loads(MCP_CONFIG.read_text())["mcpServers"]["owasp-kb"]["args"]
    assert "$HOME" in args, "the state path must be expanded by the shell, not by the harness"


def test_the_server_command_runs_the_container_without_network():
    assert "--network none" in _server_command()


PINNED_IMAGE = re.compile(
    r"\$\{OWASP_KB_IMAGE:-(ghcr\.io/[a-z0-9][a-z0-9._-]*/owasp-kb@sha256:[0-9a-f]{64})\}"
)


def test_the_default_image_is_pinned_by_digest():
    """`owasp-kb:full` resolved to docker.io/library/owasp-kb and found nothing, so
    the plugin only worked for someone who had run `make build`.

    A fully-qualified tag would reach the registry and still lose to any local
    image of that name -- `--pull=missing` is docker's default and `docker tag` is
    unprivileged. `--pull=always` would fix the shadowing by putting a registry
    round-trip and GHCR auth on the critical path of every server start, in a tool
    whose stated value is working inside a network that is deliberately locked
    down. A digest cannot be shadowed and is pulled once.

    The override is deliberately not asserted away: it is how a dev points at a
    local build and how the lite variant is selected. Only the *default* must be a
    digest.

    This asserts the shape. scripts/verify_pin.sh asserts the substance -- that the
    digest resolves and that the image it names carries the packs the lock declares.
    See ADR 0014.
    """
    args = _server_command()
    assert PINNED_IMAGE.search(args), (
        "the default image is not a digest-pinned ghcr.io reference. Run "
        "scripts/pin_image.py --image <ref> --write with a digest from a published "
        f"release; found: {args}"
    )


def test_the_state_mount_is_read_only():
    """The image gains read access to one directory and no write access at all.
    A read-only mount also sidesteps a uid mismatch: the container runs as 10001
    and the directory belongs to the host user."""
    args = _server_command()
    assert ":/state:ro" in args, "the state mount must be read-only"
    assert ':/state"' not in args, "a writable state mount would let the image modify the host"


def test_the_server_command_creates_the_state_directory_itself():
    """A bind mount whose source is missing is created by the docker daemon and
    owned by root, which the agent then cannot write to."""
    assert "mkdir -p" in _server_command()


INSTALL_SCRIPTS = (Path("install/codex.sh"), Path("install/opencode.sh"))


@pytest.mark.parametrize("script", INSTALL_SCRIPTS, ids=lambda p: p.name)
def test_the_install_scripts_carry_no_image_literal(script):
    """These print MCP config snippets for non-Claude agents, so they name the
    image too. Pasting the digest into each would give pin_image.py three literals
    to keep in step, and nothing would notice one going stale -- two internally
    consistent vocabularies with nothing translating between them, which is the
    failure #25 established and this repository keeps rebuilding.

    They read the default out of .mcp.json instead, which they can do because they
    run from the cloned repo and python3 is already a hard dependency of the hooks.
    """
    text = script.read_text()
    assert "sha256:" not in text, (
        f"{script} hardcodes a digest; it must read the default from .mcp.json so "
        "there is one literal for a release to update"
    )
    assert "owasp-kb:full" not in text, (
        f"{script} hardcodes a tag, which resolves to Docker Hub and finds nothing"
    )
    assert ".mcp.json" in text, f"{script} does not read the image from .mcp.json"


def test_all_four_skills_exist():
    found = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}
    assert found == EXPECTED_SKILLS


def _frontmatter(path: Path) -> dict:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path} has no YAML frontmatter"
    _, raw, _ = text.split("---", 2)
    return yaml.safe_load(raw)


@pytest.mark.parametrize("skill", sorted(EXPECTED_SKILLS))
def test_skill_frontmatter_has_name_and_description(skill):
    meta = _frontmatter(SKILLS_DIR / skill / "SKILL.md")
    assert meta["name"] == skill
    assert len(meta["description"]) > 120, "description is the discovery surface; make it rich"


@pytest.mark.parametrize("skill", sorted(EXPECTED_SKILLS))
def test_skill_body_mandates_tool_use_and_forbids_memory(skill):
    body = (SKILLS_DIR / skill / "SKILL.md").read_text().lower()
    assert "do not answer from memory" in body
    assert "owasp_search" in body or "owasp_checklist" in body


@pytest.mark.parametrize("skill", sorted(EXPECTED_SKILLS))
def test_skill_body_handles_an_unreachable_server(skill):
    """Silent fallback to recalled guidance is the failure mode to prevent."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text().lower()
    assert "unreachable" in body


@pytest.mark.parametrize("skill", sorted(EXPECTED_SKILLS))
def test_skills_only_reference_real_tools(skill):
    """A monorepo does not prevent plugin and server drifting apart; this does."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    # cwe_* is matched only where it is called, not bare: `cwe_corpus` is a field
    # on the owasp_roster payload, not a tool, and a bare `cwe_\w+` would flag it.
    referenced = set(re.findall(r"\b(owasp_\w+|kb_info)\b", body)) | set(
        re.findall(r"\b(cwe_\w+)\s*\(", body)
    )
    assert referenced <= TOOL_NAMES, f"unknown tools referenced: {referenced - TOOL_NAMES}"


ASSESSMENT_SKILLS = {"owasp-asvs-verify", "owasp-asvs-gap-report"}


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_scoping_discovers_prior_assessments(skill):
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    lowered = body.lower()
    assert "prior assessment" in lowered
    assert "excluded" in lowered


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_exclusion_list_reaches_the_roster(skill):
    """Discovering the reports and then not passing them to owasp_roster leaves
    the check inert -- an instruction with no consumer, again."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "excluded=" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_assessment_skills_agree_scope_before_starting(skill):
    """The scoping interaction users valued was the agent's own judgement, not the
    skill, so it would not reliably recur."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text().lower()
    assert "scope" in body
    assert "deployment context" in body or "who can reach it" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_assessment_skills_use_cumulative_level_counts(skill):
    """Levels are cumulative: an L2 assessment is 253 requirements, not 183."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "253" in body
    assert "183 at L2" not in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_assessment_skills_require_a_remediation_citation(skill):
    """A real run fetched CWEs 47 times and guidance twice, because the output
    table had a CWE column and no guidance column. An instruction with no
    downstream consumer does not get followed."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text().lower()
    assert "remediation" in body
    assert "owasp_get" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_show_a_rendered_flow_not_a_description_of_one(skill):
    """The skills said "Description carries the flow" and never showed one, so
    every finding in a real run described the trace in prose instead. An
    instruction that names an artefact without rendering it produces prose."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "SINK:" in body, "no rendered flow block for the agent to copy"
    assert "└─" in body, "the flow example is not drawn"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_require_the_offending_code_not_a_file_line(skill):
    """A real run cited every defect as file:line and quoted no source at all.
    A reader who must open the file to see the defect has a lookup, not a
    finding."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "code block" in body
    assert "^ :9" in body, "no worked example of marking the offending line"
    assert "single blameable line" in body, (
        "the no-flow case is where the code block matters most; without it an "
        "agent drops both blocks and leaves a bare file:line"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_require_remediation_as_code(skill):
    """The provenance rules said to mark 'any snippet you wrote' as yours while
    nothing ever asked for a snippet -- a rule attached to an artefact that was
    never produced, so recommendations came back as prose steps."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "Show the remediation as code when the defect is in the code" in body
    assert "Where the defect is not in the code, there is no code to show" in body, (
        "code belongs in a finding when the defect is in code. One run produced one "
        "snippet across fifteen findings, so the rule had to be stated -- but stated "
        "unconditionally it invents patches for configuration, deployment and "
        "structural defects, which misrepresents the size of the work"
    )
    for elsewhere in ("Configuration", "Deployment or an external control", "structural"):
        assert elsewhere in body, (
            f"{elsewhere!r} is a place a defect lives that has no code fix; without "
            "naming it, an agent reads the code rule as unconditional"
        )
    assert "no snippet is offered" in body, (
        "the omission must still be stated, or an agent cannot tell a considered "
        "omission from a forgotten one"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_name_the_marker_for_a_citation_that_was_read(skill):
    """The skills said "Mark the difference" and never said with what, so a real
    run invented the marker, defined its own legend and applied it to 42
    citations. That worked -- which is why nobody noticed the instruction was
    incomplete -- but it was the agent's judgement, so the next run picks a
    different glyph and two reports stop being comparable.

    The CWE half of the same section renders its examples and did recur
    correctly. This asserts the rendered form, not the mere presence of the
    character, which the legend text alone would satisfy."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "#password-storage §" in body, "no rendered example of a marked citation"
    assert "no section was read" in body, "the unmarked case is not shown beside it"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_say_an_unmarked_citation_is_not_a_failure(skill):
    """13 of 345 requirements have no guidance edge, so some citations are always
    document-level. Without this an agent reads an unmarked one as a defect and
    goes looking for a section that does not exist."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "not a defect to drive to zero" in body


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_the_skills_render_the_corpus_cwe(skill):
    """owasp_roster returns cwe_corpus and this is its only consumer. A field
    computed and never read is the inert-feature failure."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "cwe_corpus" in body


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_the_skills_distinguish_a_read_citation_from_a_mapped_one(skill):
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "remediation_quote" in body


def test_every_tool_named_in_a_skill_process_has_an_output_consumer():
    """Guard against reintroducing an instruction nothing downstream needs."""
    body = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text().lower()
    assert "owasp_get" in body
    table_line = next(line for line in body.splitlines() if "output a table" in line)
    assert "remediation" in table_line


AGENTS_DIR = Path("plugins/owasp-kb/agents")

EXPECTED_AGENTS = {
    "owasp-scope-inventory",
    "owasp-chapter-orchestrator",
    "owasp-requirement-finder",
    "owasp-exemption-refuter",
    "owasp-finding-verifier",
    "owasp-probe-runner",
}

# Agents that read the target codebase looking for evidence. `owasp-probe-runner` is
# deliberately absent: it executes a spec it is handed and never searches, so it is given
# no exclusion list at all -- the orchestrator refuses a spec naming an excluded path
# before dispatch, which keeps those paths away from the one agent holding a shell.
READING_AGENTS = EXPECTED_AGENTS - {"owasp-probe-runner"}

MCP_AGENTS = {
    "owasp-chapter-orchestrator",
    "owasp-requirement-finder",
    "owasp-finding-verifier",
}


def _agent(name: str) -> tuple[dict, str]:
    text = (AGENTS_DIR / f"{name}.md").read_text()
    assert text.startswith("---\n"), f"{name} has no frontmatter"
    _, raw, body = text.split("---", 2)
    return yaml.safe_load(raw), body


def test_the_expected_agents_exist():
    assert {p.stem for p in AGENTS_DIR.glob("*.md")} == EXPECTED_AGENTS


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_agent_declares_name_description_and_tools(name):
    """The tool allowlist is the enforcement mechanism, not documentation."""
    meta, _ = _agent(name)
    assert meta["name"] == name
    assert len(meta["description"]) > 60
    assert meta["tools"], "an agent without a tool allowlist is unconstrained"


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_no_agent_can_write(name):
    """No role is granted an editing tool. This is weaker than it reads for
    ``owasp-probe-runner``, which holds ``Bash`` and can therefore write: what stops
    it touching the target is the contract in its prompt, not the allowlist. That is
    stated in its own tests below rather than implied here."""
    meta, _ = _agent(name)
    tools = meta["tools"]
    assert "Write" not in tools
    assert "Edit" not in tools


@pytest.mark.parametrize("name", sorted(READING_AGENTS))
def test_every_reading_agent_carries_the_exclusion_rule(name):
    """A prior assessment in the target is another agent's conclusion. Every role
    that reads the codebase can stumble on one -- the verifiers did.

    ``owasp-probe-runner`` is excluded: handing the paths to the only agent with a
    shell is what the design avoids, and its output flows on to a verifier, so
    anything it read would propagate into a verdict's context. The orchestrator vets
    the spec instead."""
    _, body = _agent(name)
    assert "EXCLUDED" in body
    assert "never open" in body.lower()


def test_refuter_has_no_mcp_access():
    """It receives the exemption claim only. Handing it the requirement invites
    re-deriving the original reasoning it is meant to challenge."""
    meta, body = _agent("owasp-exemption-refuter")
    assert "ToolSearch" not in meta["tools"]
    assert "mcp__" not in meta["tools"]
    assert "mcp__" not in body


@pytest.mark.parametrize("name", sorted(MCP_AGENTS))
def test_mcp_agents_are_granted_the_mcp_server(name):
    """``tools:`` is a strict allowlist and it filters MCP tools out: 'The
    subagent can't edit files, write files, or use any MCP tools.' Granting
    ToolSearch without granting the server means ToolSearch has nothing to
    surface, and the agent correctly concludes the knowledge base is
    unreachable. The fan-out collapsed on its first real run for exactly this
    reason -- see #19. Telling an agent to ToolSearch for a tool it is not
    permitted to hold is the whole bug."""
    meta, _ = _agent(name)
    assert "mcp__plugin_owasp-kb_owasp-kb__*" in meta["tools"]


@pytest.mark.parametrize("name", sorted(MCP_AGENTS))
def test_mcp_agents_are_told_the_tools_are_deferred(name):
    """The owasp-kb tools are absent from a subagent's initial surface. An agent
    not told to ToolSearch for them concludes they do not exist and improvises."""
    meta, body = _agent(name)
    assert "ToolSearch" in meta["tools"]
    assert "ToolSearch" in body
    assert "select:mcp__plugin_owasp-kb_owasp-kb__" in body


def test_finder_cannot_return_not_applicable():
    """Exemption is decided elsewhere and must be separately refutable."""
    _, body = _agent("owasp-requirement-finder")
    assert "INSUFFICIENT EVIDENCE" in body
    assert "never return N/A" in body


def test_refuter_defaults_to_unclear_not_holds():
    _, body = _agent("owasp-exemption-refuter")
    for token in ("exemption_refuted", "exemption_holds", "unclear"):
        assert token in body
    assert "default to `unclear`" in body.lower()


def test_verifier_must_produce_a_trace():
    _, body = _agent("owasp-finding-verifier")
    assert "source" in body.lower() and "sink" in body.lower()


def test_the_verifier_gives_its_refutation_a_shape():
    """A refuted gap now needs a trace at assembly, and 'say precisely which
    mitigation defeats the claim' was prose with no field to put it in. Assert
    the JSON keys, not the words: the prose below the block names both fields,
    so a proximity check passes against an example a key was dropped from --
    the instruction-with-no-consumer rot this exists to catch. See #64."""
    _, body = _agent("owasp-finding-verifier")
    start = body.index('"verdict": "refuted"')
    block = body[start : body.index("```", start)]
    assert '"mitigations_present":' in block
    assert '"mitigation_location":' in block


def test_the_verifier_names_the_verdict_its_refutation_becomes():
    """The seam #25 burned: two internally consistent vocabularies with nothing
    translating between them."""
    from owasp_kb.core.roster import VERDICTS

    _, body = _agent("owasp-finding-verifier")
    assert "INSUFFICIENT EVIDENCE (gap refuted)" in body
    assert "INSUFFICIENT EVIDENCE (gap refuted)" in VERDICTS


def test_the_finder_attaches_the_guidance_edge():
    """0 of 72 unverified gaps in a real report carried any remediation citation,
    because the verifier is the role that produces one. guidance coverage is
    332/345, so a finder can attach the mapping itself for one tool call."""
    _, body = _agent("owasp-requirement-finder")
    assert "owasp_related" in body
    assert "guidance" in body
    assert "remediation" in body


def test_the_finder_omits_a_citation_rather_than_inventing_one():
    _, body = _agent("owasp-requirement-finder")
    lowered = body.lower()
    assert "omit" in lowered or "leave it out" in lowered


def test_the_verifier_supplies_a_quote_for_a_section_it_read():
    """An anchor that resolves proves the section exists, not that anyone read it."""
    _, body = _agent("owasp-finding-verifier")
    assert "remediation_quote" in body


def test_verify_skill_dispatches_the_agent_roles():
    body = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text()
    for agent in (
        "owasp-scope-inventory",
        "owasp-chapter-orchestrator",
        "owasp-exemption-refuter",
        "owasp-finding-verifier",
    ):
        assert agent in body, f"{agent} not dispatched"


def test_verify_skill_uses_the_roster_tool_rather_than_tallying_by_hand():
    body = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text()
    assert "owasp_roster" in body


def test_verify_skill_treats_an_exemption_as_a_refutable_claim():
    body = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text().lower()
    assert "exempt" in body
    assert "refut" in body


@pytest.mark.parametrize("skill", ["owasp-asvs-verify", "owasp-asvs-gap-report"])
def test_the_skills_document_every_uncertain_verdict(skill):
    """A report that cannot say 'I could not determine this' says MET instead.
    Read from the code rather than a hardcoded tuple: the next verdict added to
    UNCERTAIN_VERDICTS must fail this until the skills document it, instead of
    passing while the docs drift. Match the table row rather than the bare
    string -- 'INSUFFICIENT EVIDENCE' is a substring of 'INSUFFICIENT EVIDENCE
    (gap refuted)', so a containment check cannot tell whether the plain verdict
    is documented at all. See #64."""
    from owasp_kb.core.roster import UNCERTAIN_VERDICTS

    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    for verdict in sorted(UNCERTAIN_VERDICTS):
        assert f"| `{verdict}` |" in body, f"{skill} has no verdict-table row for {verdict!r}"


@pytest.mark.parametrize("skill", ["owasp-asvs-verify", "owasp-asvs-gap-report"])
def test_the_skills_record_the_trace_a_refuted_gap_needs(skill):
    """owasp_roster rejects the verdict without a trace, so a skill that names
    the verdict but not the trace produces a run that fails at assembly. The
    verdict appears several times -- the table row, the recording step, the
    detail-section rule -- so at least one of them must carry the plumbing."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    windows = [
        body[match.start() : match.start() + 900]
        for match in re.finditer(re.escape("INSUFFICIENT EVIDENCE (gap refuted)"), body)
    ]
    assert windows, f"{skill} never names the verdict"
    assert any("trace" in w and "mitigation_location" in w for w in windows), (
        f"{skill} names the verdict but never says to write the verifier's "
        "mitigation and location into the finding's trace"
    )


@pytest.mark.parametrize("skill", ["owasp-asvs-verify", "owasp-asvs-gap-report"])
def test_the_skills_consume_the_orchestrator_not_applicable_array(skill):
    """The orchestrator emits N/A claims with refuter traces. If the assembly step
    passes only `findings`, every one of them is silently re-filed as
    INSUFFICIENT EVIDENCE and the whole refutation round changes nothing."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "not_applicable" in body


def test_gap_report_dispatches_the_same_roles_as_verify():
    verify = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text()
    gap = (SKILLS_DIR / "owasp-asvs-gap-report" / "SKILL.md").read_text()
    for agent in (
        "owasp-scope-inventory",
        "owasp-chapter-orchestrator",
        "owasp-exemption-refuter",
        "owasp-finding-verifier",
    ):
        assert agent in verify and agent in gap


def test_gap_report_uses_the_roster_tool():
    body = (SKILLS_DIR / "owasp-asvs-gap-report" / "SKILL.md").read_text()
    assert "owasp_roster" in body


def test_gap_report_requires_a_remediation_citation_per_gap():
    body = (SKILLS_DIR / "owasp-asvs-gap-report" / "SKILL.md").read_text().lower()
    assert "remediation" in body
    assert "#anchor" in body


def test_orchestrator_must_not_background_its_finders():
    """It dispatched 10 finders in the background, returned early, and recovered
    0 verdicts -- see #21. Backgrounding is an observed failure, not a hypothetical."""
    _, body = _agent("owasp-chapter-orchestrator")
    lowered = body.lower()
    assert "do not run them in the background" in lowered
    assert "wait for them" in lowered


def test_orchestrator_rejects_a_finder_reply_with_no_sentinel():
    _, body = _agent("owasp-chapter-orchestrator")
    assert "REPORT COMPLETE" in body
    assert "INSUFFICIENT EVIDENCE" in body


def test_orchestrator_records_inapplicable_requirements():
    """Twelve V7 requirements were judged inapplicable with reasons and dropped
    on the floor, surfacing as INSUFFICIENT EVIDENCE -- 'could not determine'
    standing in for 'determined, does not apply'. See #23."""
    _, body = _agent("owasp-chapter-orchestrator")
    assert "N/A (verified)" in body
    assert "N/A (unverified)" in body


def test_orchestrator_batches_its_na_claims_to_one_refuter():
    _, body = _agent("owasp-chapter-orchestrator")
    lowered = body.lower()
    assert "owasp-exemption-refuter" in body
    assert "one refuter" in lowered or "a single refuter" in lowered


def test_orchestrator_maps_each_refuter_verdict_to_exactly_one_outcome():
    """`unclear` reading as both 'cannot break' and 'inconclusive' let an
    undisprovable claim be recorded as verified, with the refuter's grep line as
    its trace -- the bulk-justified exemption, rebuilt."""
    _, body = _agent("owasp-chapter-orchestrator")
    for literal in ("exemption_refuted", "exemption_holds", "unclear"):
        assert literal in body, f"{literal} is not named in the orchestrator"
    assert "`unclear` is **not** `exemption_holds`" in body


def test_the_orchestrator_forwards_the_exclusion_list_to_what_it_dispatches():
    """Finders and the batched refuter are dispatched by the orchestrator, not by
    the main session, so the orchestrator is the only thing that can give them the
    list. Their own exclusion sections are unreachable otherwise."""
    _, body = _agent("owasp-chapter-orchestrator")
    assert "Forward this list to every agent you dispatch" in body
    assert "owasp-requirement-finder" in body


def test_a_refuted_na_claim_returns_to_the_finder_queue():
    """A broken claim is a requirement that does apply after all. Dropping it
    would turn a caught mistake into a silent omission."""
    _, body = _agent("owasp-chapter-orchestrator")
    assert "refuted" in body.lower()
    assert "owasp-requirement-finder" in body


def test_refuter_handles_a_batch_of_requirement_claims():
    """One refuter per chapter, given every N/A claim at once, rather than one
    agent per claim -- twelve for V7 alone, over a hundred for a full run."""
    _, body = _agent("owasp-exemption-refuter")
    lowered = body.lower()
    assert "batch" in lowered or "list of claims" in lowered
    assert "req_id" in body


MIN_TURNS = {
    "owasp-scope-inventory": 75,
    "owasp-requirement-finder": 75,
    "owasp-exemption-refuter": 75,
    "owasp-finding-verifier": 75,
    "owasp-chapter-orchestrator": 200,
    # Builds and runs software rather than reading it: a compile-fix-run loop is
    # strictly more turn-hungry than a search, so it gets no less headroom than the
    # agents that only read.
    "owasp-probe-runner": 75,
}


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_the_turn_cap_is_a_rabbit_hole_threshold_not_a_budget(name):
    """A cap that a successful run can hit measures the wrong thing. Two inventory
    agents finished their investigation and were cut off at the moment of writing
    up, one turn short -- see #20."""
    meta, _ = _agent(name)
    assert meta["maxTurns"] >= MIN_TURNS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_every_agent_emits_a_completion_sentinel(name):
    """A truncated agent, an agent that returned early, and a finished agent all
    produce plausible text. Nothing else tells them apart."""
    _, body = _agent(name)
    assert "REPORT COMPLETE" in body


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_every_agent_is_told_to_land_before_the_cap(name):
    """The cap should only fire for genuine runaways. A role that self-reports at
    fifteen tool calls never reaches it in normal work."""
    _, body = _agent(name)
    assert "fifteen tool calls" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_assessment_skills_check_the_completion_sentinel(skill):
    """A status line and a report read alike coming back up the fan-out. The
    dispatcher has to check for the sentinel or it cannot tell them apart."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "REPORT COMPLETE" in body


def test_the_finder_emits_only_verdicts_the_roster_accepts():
    """The finder was told to return PASS; owasp_roster accepts MET; nothing
    translated. Both vocabularies were internally consistent, so 465 tests and
    five review rounds missed it and the first real end-to-end run hit it
    immediately. Seams need their own tests. See #25."""
    from owasp_kb.core.roster import VERDICTS

    meta, body = _agent("owasp-requirement-finder")
    text = f"{body} {meta['description']}"
    for rejected in ("PASS", "FAIL"):
        assert not re.search(rf"\b{rejected}\b", text), (
            f"the finder names {rejected!r}, which owasp_roster rejects; "
            f"it accepts {', '.join(VERDICTS)}"
        )
    assert "MET" in body
    assert "MET" in meta["description"]


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_the_skills_specify_per_finding_detail_sections(skill):
    """A table row cannot carry a flow, a risk assessment or a remediation with its
    provenance. See #31."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    for section in (
        "### Requirement",
        "### Description",
        "### Risk",
        "### Technical risk assessment",
        "### Recommendation",
    ):
        assert section in body, f"{skill} does not specify {section}"


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_detail_sections_are_bounded_to_verified_and_refuted_findings(skill):
    """97 gaps with a full section each would run to thousands of lines. Verified
    and refuted findings are the ones someone acts on; the rest stay table rows."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "stay table rows" in body, "the bound is what keeps a 97-gap report finite"
    assert "per **verified `GAP`**" in body
    assert "per **finding a verifier refuted**" in body


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_the_skills_require_the_verdict_in_the_finding_heading(skill):
    """A run producing 25 verified and 72 unconfirmed gaps renders them alike
    otherwise, and three quarters of the report reads as confirmed."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "verdict goes in the heading" in body.lower()


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_a_recalled_recommendation_must_say_it_is_recalled(skill):
    """The project's stated anti-goal is silent fallback to recalled guidance with
    no way to tell it from a citation. Every finding gets a recommendation; one
    without corpus backing says so."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "training data" in body
    assert "hallucinated" in body
    assert "Every finding gets one" in body


@pytest.mark.parametrize("skill", ASSESSMENT_SKILLS)
def test_risk_scoring_flags_metrics_the_code_cannot_settle(skill):
    """Confidentiality and Integrity depend on what a credential grants, which is a
    business input. Scoring them silently presents a guess as an assessment."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "CVSS" in body
    assert "cannot settle" in body
    assert "temporal or environmental" in body


def test_pyproject_derives_its_version_rather_than_repeating_it():
    """importlib.metadata reads install-time metadata, so an editable install
    reports a stale version after a bump until reinstalled. Deriving from the
    module attribute keeps one literal in the repo."""
    text = Path("pyproject.toml").read_text()
    assert 'dynamic = ["version"]' in text
    assert 'attr = "owasp_kb.__version__"' in text
    assert '\nversion = "' not in text, "a literal version in pyproject is a second source of truth"


def test_the_repo_carries_a_cwe_license_text():
    """CWE's terms are not in the catalogue XML -- they are a separate document.
    Vendored rather than fetched at build time: a legal notice should not change
    silently between builds, and a --network none image must carry it."""
    text = Path("licenses/LICENSE-CWE").read_text()
    assert "CWE" in text
    assert len(text) > MIN_LICENCE_BYTES, "a stub is not the terms"


# Any real licence text is kilobytes; the shortest here is CWE's terms at ~2.6 KB.
# The point is to reject a zero-byte or one-line placeholder that satisfies "the
# file exists" while carrying no terms at all.
MIN_LICENCE_BYTES = 500

CC_BY_SA_TEXTS = (
    Path("licenses/LICENSE-OWASP-ASVS"),
    Path("licenses/LICENSE-OWASP-CHEATSHEET"),
)


def test_the_two_cc_by_sa_texts_are_identical():
    """ASVS and the Cheat Sheet Series are both CC-BY-SA-4.0, so each pack's
    licence file is a copy of one 20 KB text. Two copies of legal text is the
    shape that drifts: one gets updated and the repository then makes two
    different claims about the same licence, silently.

    Bytes, not text -- a line-ending change is drift. Non-emptiness is asserted
    first because two empty files are also identical, and that is the way this
    assertion passes while proving nothing.

    If this ever fails, reconcile the two files. Deleting the test is not the
    fix; if the upstreams have genuinely relicensed apart, that is the news and
    sources.lock.yml should say so before these files do."""
    asvs, cheatsheets = (path.read_bytes() for path in CC_BY_SA_TEXTS)
    assert len(asvs) > MIN_LICENCE_BYTES, f"{CC_BY_SA_TEXTS[0]} is a stub, not a licence"
    assert asvs == cheatsheets, (
        f"{CC_BY_SA_TEXTS[0]} and {CC_BY_SA_TEXTS[1]} have drifted apart; both "
        "are CC-BY-SA-4.0 and must be the same text"
    )


LOCK_FILE = Path("sources.lock.yml")


def _lock_packs() -> dict:
    return yaml.safe_load(LOCK_FILE.read_text())["packs"]


PACK_LICENCE_FILES = {
    "asvs": Path("licenses/LICENSE-OWASP-ASVS"),
    "cheatsheets": Path("licenses/LICENSE-OWASP-CHEATSHEET"),
    "cwe": Path("licenses/LICENSE-CWE"),
}

# What a licence's own text says about itself, so a pack's file can be checked
# against the SPDX id the lock declares for it rather than merely existing. The
# markers are each absent from the other text, which is what makes a
# transposition detectable.
LICENCE_TEXT_MARKERS = {
    "CC-BY-SA-4.0": "Attribution-ShareAlike 4.0 International",
    "LicenseRef-CWE-TOU": "CWE Terms of Use",
}


def test_every_pack_in_the_lock_has_its_own_licence_text():
    """sources.lock.yml declares a licence per pack. Until this branch the files
    did not: one CC-BY-SA-4.0 text covered two packs, so a redistributor could
    not resolve a shipped pack to the text governing it, and an upstream
    relicensing one of the two had no file to change.

    Both directions, and derived from the lock rather than from a list of three:
    a fourth pack added without a licence text fails here, and so does a licence
    text left behind for a pack that has been dropped.

    The set-equality and size checks alone are structural: they pass on a
    mapping with the right keys pointing at real, non-stub files even if a
    pack's file is transposed with a different pack's. Mutating
    PACK_LICENCE_FILES["cwe"] to point at the ASVS text -- real, well over the
    stub threshold, just the wrong pack's terms -- passed both checks above
    silently. So each mapped file's text is also checked against the SPDX id
    the lock declares for its pack: the file has to identify itself as the
    licence it claims to be, not just exist and be large enough. This cannot
    tell asvs and cheatsheets apart from one another -- both are CC-BY-SA-4.0
    and, per the identity test above, byte-identical, so a transposition
    between those two specifically leaves no content difference to detect."""
    packs = _lock_packs()
    assert set(PACK_LICENCE_FILES) == set(packs), (
        f"licence files cover {sorted(PACK_LICENCE_FILES)}, the lock has {sorted(packs)}"
    )
    for name, path in sorted(PACK_LICENCE_FILES.items()):
        assert path.is_file(), f"pack {name!r}: {path} does not exist"
        assert path.stat().st_size > MIN_LICENCE_BYTES, (
            f"pack {name!r}: {path} is {path.stat().st_size} bytes, which is a "
            "stub and not a licence"
        )
        licence_id = packs[name]["license"]
        if licence_id not in LICENCE_TEXT_MARKERS:
            raise AssertionError(
                f"pack {name!r} declares licence {licence_id!r}, which has no "
                "entry in LICENCE_TEXT_MARKERS; add one so its text can be "
                "checked"
            )
        marker = LICENCE_TEXT_MARKERS[licence_id]
        text = path.read_text()
        assert marker in text, (
            f"pack {name!r}: {path} does not contain {marker!r}, the marker "
            f"for the {licence_id!r} the lock declares for this pack"
        )


def _dockerfile_targets(text: str) -> dict[str, str]:
    """Split a Dockerfile into {target_name: body}. Both image variants must
    carry the licenses; a whole-file substring search cannot tell one from two,
    because the two blocks are identical.

    Blind spot: a `FROM <image>` line with no `AS <name>` does not match, so its
    lines silently fold into the previous named stage instead of raising. Every
    stage in this Dockerfile is named, so this has not been exercised -- do not
    trust this helper on a Dockerfile with an unnamed stage without checking."""
    blocks: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        match = re.match(r"^FROM\s+.*\sAS\s+(\S+)", line, re.IGNORECASE)
        if match:
            name = match.group(1)
            blocks[name] = ""
        elif name:
            blocks[name] += line + "\n"
    return blocks


EXPECTED_LICENSE_NAMES = {
    "LICENSE",
    "LICENSE-OWASP-ASVS",
    "LICENSE-OWASP-CHEATSHEET",
    "LICENSE-CWE",
    "NOTICE",
}
EXPECTED_LICENSES_LABEL = "MIT AND CC-BY-SA-4.0 AND LicenseRef-CWE-TOU"


@pytest.mark.parametrize("target_name", ["lite", "full"])
def test_the_dockerfile_ships_every_license_text(target_name):
    """The image shipped an OCI label and no notice. docs/licensing.md asks a
    redistributor to keep each pack's licence text with the artifact; the image
    did not.
    Checked per target, not as a whole-file substring search: the lite and
    full blocks are otherwise identical, so a whole-file search cannot tell
    whether one target's COPY or LABEL was missed entirely."""
    dockerfile = Path("docker/Dockerfile").read_text()
    targets = _dockerfile_targets(dockerfile)
    assert {"lite", "full"} <= targets.keys(), (
        "the target parser found neither block -- without this, a missing stage "
        "fails on `targets[target_name]` with a bare KeyError naming nothing useful"
    )
    body = targets[target_name]

    copy_lines = [
        line
        for line in body.splitlines()
        if line.strip().startswith("COPY") and "/opt/owasp-kb/licenses/" in line
    ]
    assert len(copy_lines) == 1, (
        f"{target_name}: expected exactly one COPY into /opt/owasp-kb/licenses/, "
        f"found {len(copy_lines)}"
    )
    tokens = copy_lines[0].split()
    assert tokens[0] == "COPY"
    assert tokens[-1] == "/opt/owasp-kb/licenses/"
    # Sources are repo-relative paths now that the texts live under licenses/,
    # and COPY into a directory flattens them to basenames in the image.
    sources = [Path(token) for token in tokens[1:-1]]
    copied_names = {source.name for source in sources}
    assert copied_names == EXPECTED_LICENSE_NAMES, (
        f"{target_name}: COPY names {copied_names}, expected {EXPECTED_LICENSE_NAMES}"
    )
    # A rename leaves the COPY pointing at a path that is gone. The names above
    # still match, and only a docker build would notice -- which CI does not run
    # on every change.
    for source in sources:
        assert source.is_file(), f"{target_name}: COPY names {source}, which is not in the tree"

    label_match = re.search(r'org\.opencontainers\.image\.licenses="([^"]*)"', body)
    assert label_match, f"{target_name}: no org.opencontainers.image.licenses label"
    assert label_match.group(1) == EXPECTED_LICENSES_LABEL, (
        f"{target_name}: licenses label is {label_match.group(1)!r}, "
        f"expected {EXPECTED_LICENSES_LABEL!r}"
    )


def test_licensing_doc_covers_cwe():
    text = Path("docs/licensing.md").read_text()
    assert "CWE" in text
    assert "mitre trademark" in text.lower(), (
        "this is the sentence the new CWE section introduced; distinct from "
        "the pre-existing OWASP trademark disclaimer, which never says MITRE"
    )


# One string per file, and each one is something the CWE *pack* introduced.
# The assertion originally written here was `"CWE" in text` for all three, and it
# could not fail for two of them: docs/stack.md and docs/kb-packs.md both said
# "CWE" before this branch existed, because the ASVS->CWE *mapping* has been
# ingested since 0.2.0. A file can satisfy that and still describe a two-pack,
# all-OWASP server, which is the exact claim this test is here to catch.
CWE_PACK_MARKERS = {
    # None of the three tools existed before the pack; the README's job here is
    # to list them, so the tool name is the pack's footprint in it.
    "README.md": "cwe_get",
    # The sentence the framing turns on. docs/licensing.md already carried it;
    # docs/stack.md is where a reader goes to learn what the corpus *is*.
    "docs/stack.md": "not an OWASP project",
    # The third pack type. `catalogue` is CWE's and nothing else's, so a
    # kb-packs.md that still documents two types cannot contain it.
    "docs/kb-packs.md": "catalogue",
}


@pytest.mark.parametrize("path", sorted(CWE_PACK_MARKERS))
def test_the_docs_do_not_claim_every_pack_is_owasp(path):
    """CWE is MITRE's. A project called owasp-kb that silently serves non-OWASP
    content misattributes it, and a reader cannot tell which upstream a citation
    came from."""
    marker = CWE_PACK_MARKERS[path]
    text = Path(path).read_text()
    assert "CWE" in text, f"{path} does not mention the CWE pack"
    assert marker in text, (
        f"{path} mentions CWE but not {marker!r} -- it may only be talking about "
        "the ASVS->CWE mapping, which predates the pack"
    )


def test_the_smoke_test_covers_every_advertised_tool():
    """The loop checked the original seven. A shipped image whose cwe_get was
    missing would have passed, which is the one thing a smoke test is for."""
    script = Path("scripts/docker_smoke.sh").read_text()
    loop = next(line for line in script.splitlines() if line.startswith("for tool in "))
    checked = set(loop.removeprefix("for tool in ").removesuffix("; do").split())
    assert checked == TOOL_NAMES, f"smoke test misses {TOOL_NAMES - checked}"


def test_the_smoke_test_proves_the_licence_texts_reached_the_image():
    """Task 1 added the COPY and tested only the Dockerfile text. Nothing ran
    against a built image, so `it should work` was as far as it went.

    Unexercised until someone runs `make docker-smoke`: this asserts the script
    contains the check, not that the check passes."""
    script = Path("scripts/docker_smoke.sh").read_text()
    for name in EXPECTED_LICENSE_NAMES:
        assert f"/opt/owasp-kb/licenses/{name}" in script, (
            f"the smoke test never looks for {name} in the image"
        )


# A tool the agent is told to *call*, as opposed to one merely described. The
# roster is named in every agent as the thing that will reject their output --
# "owasp_roster rejects a finding that cites an excluded path" -- and no agent
# calls it, so a plain mention is not evidence of use.
_TOOL = r"(?:kb_info|owasp_\w+|cwe_\w+)"
_CALL_FORM = re.compile(rf"`({_TOOL})\(")
_IMPERATIVE = re.compile(rf"\b(?:use|call|run)\s+`({_TOOL})`", re.IGNORECASE)


def _tools_instructed(body: str) -> set[str]:
    return {m.group(1) for m in _CALL_FORM.finditer(body)} | {
        m.group(1) for m in _IMPERATIVE.finditer(body)
    }


def _tools_loaded(body: str) -> set[str]:
    return set(re.findall(r"select:mcp__plugin_owasp-kb_owasp-kb__(\w+)", body))


def test_the_call_detector_actually_matches_something():
    """Guard on the two tests below. Both assert instructed <= loaded, which an
    empty instructed set satisfies trivially -- so if these patterns stop
    matching, the coverage checks pass while enforcing nothing."""
    _, body = _agent("owasp-finding-verifier")
    found = _tools_instructed(body)
    assert {"cwe_get", "owasp_related"} <= found, (
        f"the detector found {sorted(found)}; it is no longer reading the file"
    )


@pytest.mark.parametrize("agent", sorted(EXPECTED_AGENTS))
def test_every_tool_an_agent_is_told_to_call_is_loaded(agent):
    """The plugin's MCP tools are deferred: an agent must be permitted by its
    tools: allowlist *and* load the schema via ToolSearch. The allowlist is the
    check people make, and it is only half. owasp_search was instructed and
    never loaded, so that instruction silently did nothing."""
    _, body = _agent(agent)
    missing = _tools_instructed(body) - _tools_loaded(body)
    assert not missing, f"{agent} is told to call {sorted(missing)} but never loads it"


def test_the_verifier_returns_the_code_it_read():
    """The verifier returned source/sink/path as prose and no code, so the
    report author had to re-open every file it had already read -- which is
    where a wrong line number gets introduced."""
    _, body = _agent("owasp-finding-verifier")
    assert '"snippet"' in body, "no snippet field in the output contract"
    # Emphasis markers fall inside the phrase ("**not** read by"), so strip them
    # rather than pinning the assertion to today's formatting.
    assert "not read by `owasp_roster`" in body.replace("*", ""), (
        "the agent is told elsewhere that invented roster fields are inert; "
        "without naming this field's real consumer it reads as one of those"
    )


def test_the_verifier_does_not_downgrade_a_single_line_defect():
    """'A confirmation without a source and a sink is not a confirmation' would
    return unclear for a wrong constant or an unset flag, which has no taint
    path and never will. A false negative here is the expensive direction."""
    _, body = _agent("owasp-finding-verifier")
    assert "single blameable line" in body
    assert "not being unable to draw an arrow" in body


def test_the_verifier_verifies_a_cwe_it_did_not_get_from_the_mapping():
    """Of 95 CWE ids cited in one real assessment, 42 were not from OWASP's
    mapping and nothing could check them. cwe_get is what checks them."""
    _, body = _agent("owasp-finding-verifier")
    assert "cwe_get" in body


def test_the_verifier_can_actually_call_the_cwe_tools_it_is_told_to_call():
    """The highest-risk failure in this change and the cheapest to miss: `tools:`
    is a strict allowlist that filters MCP tools, so prose telling the agent to
    call cwe_get is inert -- worse than inert, it is an agent that cannot do what
    its own prompt instructs -- if the allowlist does not reach it.

    It does, via the server wildcard, which is why no frontmatter change shipped
    with the prose. This test is what makes that a checked fact rather than an
    assumption: an allowlist later narrowed to an enumeration of tool names would
    silently break the guidance below, and nothing else would notice."""
    meta, body = _agent("owasp-finding-verifier")
    allowed = {t.strip() for t in meta["tools"].split(",")}
    server = "mcp__plugin_owasp-kb_owasp-kb__"
    named = [t for t in ("cwe_get", "cwe_search", "cwe_related") if t in body]
    # Without this the loop below has nothing to iterate and the test passes on a
    # prompt that never mentions a CWE tool at all -- vacuous rather than green.
    assert named, "the verifier prompt names none of the CWE tools"
    for tool in named:
        assert f"{server}*" in allowed or f"{server}{tool}" in allowed, (
            f"the prompt tells the agent to call {tool} and the tools: allowlist "
            f"does not permit it -- {allowed}"
        )


def test_the_verifier_is_told_to_load_the_cwe_tools_before_calling_them():
    """MCP tools are deferred in this plugin: the agent must ToolSearch a tool's
    schema before it can be invoked, and the existing section enumerates which.
    A cwe_get missing from that list is a tool the agent is told to call and has
    no schema for."""
    _, body = _agent("owasp-finding-verifier")
    assert "select:mcp__plugin_owasp-kb_owasp-kb__cwe_get" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_cite_the_weakness_name_not_just_the_id(skill):
    """`cwe_get` alone would pass on a skill that merely names the tool. The point
    of the guidance is the name beside the id: a reader cannot judge CWE-789 and
    can judge 'Memory Allocation with Excessive Size Value'."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "cwe_get" in body
    assert "weakness **name**" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_say_an_obsolete_mapping_is_grounds_to_depart(skill):
    """CWE-320 is Obsolete and eight requirements map to it. That is the clearest
    case for substituting a specific weakness, and it is now evidenceable.

    Asserted on the phrase, not the bare word: `"Obsolete" in body` was the
    assertion first written here, and a bare word carries no instruction -- a
    skill could satisfy it while saying nothing about what to do, and any
    incidental future mention would keep satisfying it."""
    # Whitespace-normalised: the phrase wraps across a line break in both files,
    # and where a hard wrap falls is not what this test is about.
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "`Obsolete` or is a Category rather than a weakness" in body


NOTICE_FILE = Path("licenses/NOTICE")


def _notice_attribution_entries() -> list[str]:
    """The `- `-prefixed blocks of NOTICE's attribution list, one per upstream.

    Parsed as blocks rather than searched as substrings, and that is the whole
    point of this helper. A bare `"CWE" in notice` check passes on a NOTICE that
    never attributes CWE at all, because the string occurs in `LICENSE-CWE` and
    inside `LicenseRef-CWE-TOU` in the prose. So does `"cheatsheets" in
    notice.lower()`, off the `CheatSheetSeries` URL of a different pack. Scoping
    to the list means a pack is only found where it is actually attributed.
    """
    blocks = NOTICE_FILE.read_text().split("\n\n")
    return [b for b in blocks if b.lstrip().startswith("- ")]


def _upstream_marker(name: str, pack: dict) -> str:
    """Where a pack's attribution entry must point, derived from its lock entry.

    Two shapes exist because the upstreams differ: ASVS and the Cheat Sheet
    Series are GitHub repositories (`repo`), CWE is a direct download from
    MITRE (`url`). A pack carrying neither fails loudly rather than being
    skipped -- an unlocatable upstream is not an attributable one.
    """
    if repo := pack.get("repo"):
        return f"https://github.com/{repo}"
    if url := pack.get("url"):
        host = urlparse(url).netloc
        assert host, f"pack {name!r} has an unparseable url {url!r}"
        return host
    raise AssertionError(
        f"pack {name!r} declares neither `repo` nor `url`, so NOTICE has no "
        "upstream to attribute; give the lock entry one"
    )


def test_notice_ships_as_plain_text_not_markdown():
    """NOTICE is COPY'd into both images at /opt/owasp-kb/licenses/ and is read
    there as a text file, so a markdown `**` renders as four literal asterisks in
    the middle of a licence notice. Three crept in when the CWE attribution was
    added; master's NOTICE had none."""
    assert "**" not in NOTICE_FILE.read_text(), (
        "markdown emphasis in NOTICE renders literally where it ships"
    )


def test_notice_attributes_every_pack_in_the_lock():
    """NOTICE said "two upstream OWASP projects" for the whole of this branch,
    while the image baked a third pack that is MITRE's and not CC-BY-SA-4.0 --
    contradicting the OCI licence label in the same artifact. It went stale
    because nothing asserted anything about it at all.

    Derived from sources.lock.yml, not from a list of three: a fourth pack added
    without touching NOTICE fails here."""
    packs = _lock_packs()
    entries = _notice_attribution_entries()
    assert len(entries) == len(packs), (
        f"NOTICE lists {len(entries)} upstreams and the lock has {len(packs)}"
    )
    for name, pack in sorted(packs.items()):
        marker = _upstream_marker(name, pack)
        matched = [e for e in entries if marker in e]
        assert len(matched) == 1, (
            f"pack {name!r}: expected exactly one NOTICE attribution entry "
            f"pointing at {marker}, found {len(matched)}"
        )


def test_notice_states_each_packs_licence_on_that_packs_own_entry():
    """Not "the licence string appears in NOTICE somewhere": LicenseRef-CWE-TOU
    also appears in the composite-index paragraph, so a file-wide search would
    pass with the licence stated against the wrong upstream, or against none."""
    entries = _notice_attribution_entries()
    for name, pack in sorted(_lock_packs().items()):
        marker = _upstream_marker(name, pack)
        # Asserted, not `next(...)`: a bare StopIteration reports as an error that
        # names neither the pack nor what was looked for.
        matched = [e for e in entries if marker in e]
        assert matched, f"pack {name!r}: no NOTICE entry points at {marker}"
        entry = matched[0]
        stated = re.search(r"^\s*License:\s*(\S+)", entry, re.MULTILINE)
        assert stated, f"pack {name!r}: its NOTICE entry has no `License:` line"
        assert stated.group(1) == pack["license"], (
            f"pack {name!r}: NOTICE says {stated.group(1)!r}, the lock says {pack['license']!r}"
        )


def test_notice_does_not_claim_one_licence_covers_the_whole_index():
    """The sentence was "The index therefore remains CC-BY-SA-4.0 in its own
    right". That is a licensing claim, not an attribution one, and it is false
    once the index contains MITRE content that is not CC-BY-SA-4.0. The index is
    a composite; NOTICE has to say which portion is which.

    Matched case-insensitively and without the emphasis marker: NOTICE ships as
    plain text at /opt/owasp-kb/licenses/, where markdown `**` renders literally,
    so how the sentence emphasises "composite" is free to change. What must not
    change is that it says so at all."""
    notice = " ".join(NOTICE_FILE.read_text().split()).lower()
    assert "index therefore remains cc-by-sa-4.0 in its own right" not in notice
    assert "of differently-licensed content" in notice
    licences = {p["license"] for p in _lock_packs().values()}
    assert len(licences) > 1, (
        "every pack now shares one licence, so the composite wording above is no "
        "longer the thing to assert -- revisit this test rather than deleting it"
    )


def test_the_image_tag_records_every_packs_version():
    """asvs$(V)-cs$(DATE) named two of three packs, so a CWE bump produced an
    indistinguishable tag for a different index. The immutable tag is the whole
    basis of the reproducible-citation promise, and cwe_get means CWE ids are
    now part of what it promises."""
    makefile = Path("Makefile").read_text()
    release = Path(".github/workflows/release.yml").read_text()
    assert "CWE_VERSION" in makefile, "the Makefile does not read the CWE version"
    for text, name in ((makefile, "Makefile"), (release, "release.yml")):
        assert "-cwe" in text, f"{name} builds a tag that does not name the CWE pack"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_accumulate_findings_on_disk(skill):
    """owasp_roster gained a session parameter that reads findings.jsonl, and
    nothing told an agent to write one -- a consumer with no producer, which is
    the inert-feature failure this project keeps shipping. Without this the
    feature exists and is never reached."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "findings.jsonl" in body, "nothing writes the file the roster reads"
    assert "session=$CLAUDE_CODE_SESSION_ID" in body, "the roster is never told which session"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_say_a_correction_is_an_appended_line(skill):
    """The saving only materialises if corrections append. An agent that rewrites
    the file pays the full cost anyway and loses the amendment history."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "append a corrected line for the same `req_id`" in body
    assert "Do not rewrite the file" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_write_the_report_in_sections(skill):
    """The report was the only stage of an assessment that was not incremental:
    one 120,000-character write at the end, larger than the checklist call that
    already proved undeliverable."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "owasp-kb report merge" in body, "no merge step, so sections would never be assembled"
    assert "--expect-findings" in body, (
        "without the count the merge cannot detect a finding with no detail section"
    )
    assert "301_finding_1.md" in body, "no rendered example of the section naming"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_forbid_concatenating_sections_by_hand(skill):
    """Re-reading forty sections to join them costs the context this exists to
    save, and a dropped one would go unnoticed."""
    # Normalised: the sentence wraps differently in the two skills, and pinning
    # the assertion to today's line breaks makes it fail on a reflow.
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "Do not concatenate the sections yourself" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_arm_the_exclusion_hook(skill):
    """The PreToolUse hook reads sessions/<id>/excluded and nothing wrote it, so
    it would have allowed everything in a real run -- a consumer with no
    producer, the same gap findings.jsonl had. It fails open by design, so an
    unarmed hook is indistinguishable from one with nothing to block."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "sessions/$CLAUDE_CODE_SESSION_ID/excluded" in body, "nothing arms the hook"
    assert "the hook stops the read" in body, (
        "the three controls must be distinguished, or one is assumed to cover the others"
    )


def test_the_plugin_registers_the_inventory_gate_against_a_dispatch():
    """A hook the manifest does not register never runs, and the gate is the whole
    point of the file: prose asking for a complete inventory is the instruction
    class #58 replaced. Both dispatch tool names are matched -- `Task` in the
    harness this plugin targets, `Agent` elsewhere -- because matching one leaves
    the gate inert wherever the other is used."""
    hooks = json.loads(PLUGIN.read_text())["hooks"]["PreToolUse"]
    gate = [entry for entry in hooks if "gate_triage_on_inventory" in json.dumps(entry)]
    assert len(gate) == 1, "the inventory gate is not registered exactly once"
    matcher = gate[0]["matcher"]
    assert "Task" in matcher and "Agent" in matcher, f"matcher {matcher!r} misses a dispatch tool"
    assert Path("plugins/owasp-kb/hooks/gate_triage_on_inventory.py").exists()


def test_the_plugin_registers_the_security_flag_hook():
    """A hook the manifest does not register never runs, and this is the only
    mechanism here that fires without being chosen -- which is the point, since the
    skill was seen and chosen against."""
    hooks = json.loads(PLUGIN.read_text())["hooks"]
    entries = hooks.get("UserPromptSubmit") or []
    flagged = [e for e in entries if "flag_security_topic" in json.dumps(e)]
    assert len(flagged) == 1, "the security flag hook is not registered exactly once"
    assert "matcher" not in flagged[0], (
        "UserPromptSubmit carries no matcher -- there is no tool name to match, and "
        "an ignored key reads as a filter that is being applied"
    )
    assert Path("plugins/owasp-kb/hooks/flag_security_topic.py").exists()


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_arm_the_inventory_gate(skill):
    """The concerns list arms the gate and inventory.md satisfies it. Nothing else
    can see this stage -- owasp_roster counts verdicts and the inventory produces
    facts -- and one run had four of five inventory agents return, then triaged all
    seventeen chapters over the hole. See #60.

    The ordering is load-bearing: a list written after the returns leaves the gate
    inert for exactly the run it was meant to gate."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "sessions/$CLAUDE_CODE_SESSION_ID/concerns" in body, "nothing arms the gate"
    assert "sessions/$CLAUDE_CODE_SESSION_ID/inventory.md" in body, "no artefact to satisfy it"
    assert "before those agents go out" in body, "the list must precede the dispatches"
    assert "no client-side surface exists in this target" in body, (
        "the way past the gate for a concern that found nothing must be stated, or an "
        "empty heading becomes the workaround"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_keep_a_dispatch_ledger(skill):
    """A run wrote this ledger unprompted, including the verifier queue -- the one
    stage that starved in it. #47 established that an unprompted behaviour does not
    recur, and #50 that an instruction naming an outcome without a rendered example
    produces prose instead of the artefact, so the block appears verbatim. See #60."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "sessions/$CLAUDE_CODE_SESSION_ID/pending.txt" in body, "no ledger"
    assert "INVENTORY returned:" in body, (
        "the ledger must cover the inventory stage, which is the one owasp_roster cannot see"
    )
    assert "GAPS AWAITING VERIFIER" in body, "the queue that starved is the one worth tracking"


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_gate_the_report_on_verification_completing(skill):
    """A run shipped a report with 35 of 51 gaps unverified. Nothing was broken:
    complete means every requirement carries a verdict, the agent read that as
    the assessment being done, and proceeded. The gate the design lacked."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "verification_complete" in body, "no gate on the verification stage"
    assert "repeat until `verification_complete` is true" in body, "stated, but not a loop"
    assert "`unassessed`" in body, (
        "the finder stage is gated too: a requirement nobody looked at and one a finder "
        "could not determine are both INSUFFICIENT EVIDENCE, and only one is a result"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_treat_a_failed_dispatch_as_transient(skill):
    """The concurrency limit produced 35 unconfirmed gaps in one run. A spawn
    failure is not a verdict, and accepting the downgrade makes giving up
    indistinguishable from honest reporting."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "A dispatch that errors is not a verdict" in body
    assert "Dispatch fewer at once and retry" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_require_an_uncleared_shortfall_to_be_stated(skill):
    """If it cannot be cleared, the report must say so with the count and the
    reason -- otherwise a reader cannot tell an unverified gap from a tested
    one, which is the whole problem restated."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "say so in the Results section" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_say_when_each_section_can_be_written(skill):
    """A real run wrote the title two minutes in, on its own initiative, then
    batched all seventeen chapter rosters into one moment and serialised the
    findings at the end -- 17 of 64 minutes spent writing after verification had
    finished. The prefix decides order, so none of that had to be serial.

    The roster row named the orchestrator, whose verdicts are not settled: 62
    gaps were reported on one run and 32 refuted, so the row asked for a section
    that would have been wrong for half its rows. An instruction whose
    precondition never arrives gets batched to the end, correctly. See #63."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "Can be written as soon as" in body, "no dependency table"
    assert "that chapter's** verifiers return" in body, (
        "the roster row must wait for settled verdicts, not the orchestrator"
    )
    assert "**each** refuter returns" in body, (
        "the exemptions row batched every refuter into one moment"
    )
    assert "Only the summary genuinely has to come last" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_dispatch_the_refuters_at_triage(skill):
    """A refuter needs the triage decision and the inventory, nothing else. It sat
    inside the verification stage only because both were called verification, so a
    refuted exemption returned its chapter to scope after every other chapter had
    already finished. See #63.

    Two checks, because they catch different regressions: the positional one below
    pins where the *dispatch bullet* sits, which catches it moving out of triage but
    not a second dispatch added back inside the chapter block; the bounded-slice
    check after it catches that half.

    The bullet rather than the first mention of the role: the inventory gate names
    both gated roles in step 2, so a first-mention check now pins the gate's
    description of the refuter instead of the dispatch of one."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    triage = body.index("Triage applicability yourself")
    pillar = body.index("Run each chapter to completion")
    refuter = body.index("`EXEMPT` → one `owasp-exemption-refuter`")
    assert triage < refuter < pillar, f"{skill} dispatches the refuters outside the triage step"

    normalised = " ".join(body.split())
    start = normalised.index("Run each chapter to completion")
    block = normalised[start : normalised.index("5. **Assemble with", start)]
    assert "owasp-exemption-refuter" not in block, (
        f"{skill} dispatches a refuter inside the chapter block"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_main_agent_dispatches_the_verifier_not_the_orchestrator(skill):
    """Independence is structural, not instructed: the main agent holds only the
    orchestrator's condensed JSON, so a finder's argument cannot reach the verifier
    through it. Pipelining changes when the verifier is dispatched, never by whom --
    and the orchestrator, which does hold the finder's full text, is the one place
    that dispatch must not move to. See #63."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    start = body.index("Run each chapter to completion")
    block = body[start : body.index("5. **Assemble with", start)]
    assert "you dispatch it, not the orchestrator" in block, (
        f"{skill} does not say who dispatches the verifier"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_a_chapter_roster_section_waits_for_that_chapters_verifiers(skill):
    """The whole reason the old row was unachievable: an orchestrator returns
    pre-verification verdicts. See #63."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    start = body.index("Run each chapter to completion")
    block = body[start : body.index("5. **Assemble with", start)]
    assert "once its verifiers have returned" in block, (
        f"{skill} does not tie the roster section to settled verdicts"
    )


def test_the_orchestrator_still_refuses_to_verify_its_own_findings():
    """The other half of the same guarantee, in the other file. Moving the
    verifier dispatch earlier must not move it into the orchestrator, which holds
    every finder's full text. See #63."""
    _, body = _agent("owasp-chapter-orchestrator")
    assert "You do not verify findings" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_summary_is_gated_on_verification_completing(skill):
    """101_summary quotes the roster's final counts. Written before the loop
    clears, it reports numbers that are still moving."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "cannot be written until `verification_complete`" in body


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_require_the_root_cause_reduction_as_a_ratio(skill):
    """A run stated '51 gap entries are not 51 independent problems. They reduce
    to five.' -- the single most useful line for someone deciding what to fix
    first, and not asked for. The rendered example is deliberate: #50 showed an
    instruction naming an outcome without one produces prose instead."""
    text = (SKILLS_DIR / skill / "SKILL.md").read_text()
    body = " ".join(text.split())
    assert "State the root-cause reduction as a number" in body
    assert "> 51 gap entries are not 51 independent problems. They reduce to five." in text, (
        "the example has to be rendered, not described -- an instruction that "
        "names the outcome yields a list without the count"
    )


@pytest.mark.parametrize("skill", sorted(ASSESSMENT_SKILLS))
def test_the_skills_name_the_report_to_mark_it_independent(skill):
    """Two assessments of one target at one level differ only by filename, and
    the excluded one is what a reader reaches for by mistake. A run invented both
    the '-independent-<date>' suffix and the sentence saying the priors were
    never opened."""
    body = " ".join((SKILLS_DIR / skill / "SKILL.md").read_text().split())
    assert "-independent-<YYYY-MM-DD>.md" in body
    assert "never opened" in body, (
        "the filename alone does not say the priors went unread; without the "
        "sentence a reader assumes this report built on them"
    )


def test_ci_ignores_only_paths_no_test_reads():
    """A `paths-ignore` entry covering a path the suite asserts against would
    stop verifying it, silently and only for changes to that path.

    The list has to stay narrow because `test` reads far more of the tree than
    its name suggests -- NOTICE, README.md, three files under docs/, the
    Dockerfile, the Makefile, sources.lock.yml and everything under plugins/.
    Enumerating the safe paths by hand is how that drifts, so this compares the
    ignore patterns against every repo-relative path literal in tests/ and fails
    on an overlap. Adding a test that reads an ignored path is then a failure
    here rather than a check that quietly stopped running.
    """
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
    # YAML 1.1 reads a bare `on:` as the boolean True, so the trigger block is
    # not under the key it is written as.
    triggers = workflow.get("on") or workflow[True]
    patterns = triggers["pull_request"]["paths-ignore"]
    assert patterns, "no paths-ignore to check"

    literals = set()
    for source in Path("tests").glob("*.py"):
        for match in re.finditer(r'"((?:[\w.-]+/)+[\w.-]+)"', source.read_text()):
            candidate = match.group(1)
            if Path(candidate).exists():
                literals.add(candidate)
    assert literals, "found no path literals, so this test would pass vacuously"

    for pattern in patterns:
        prefix = pattern.removesuffix("/**").removesuffix("/*")
        hit = sorted(p for p in literals if p == prefix or p.startswith(f"{prefix}/"))
        assert not hit, (
            f"ci.yml ignores {pattern!r} but the suite reads {hit} -- a change to "
            "those files would skip the tests that assert on them"
        )


EXPECTED_RUNNER = "ubuntu-latest"


def test_every_job_runs_on_the_same_deliberately_chosen_runner():
    """Where CI runs is a choice, and a job that drifts off it still passes -- it
    just runs somewhere nobody decided on, and nothing reports that. This assertion
    is the only available signal, whichever runner is chosen.

    It was `arc-runner-set` for one day. The org's self-hosted pool turned out to be
    exhausted by other repositories: with six concurrent full builds queued, the
    ~25-minute `build` job stopped starting at all and the queue had to be cancelled
    by hand. Four jobs came back to `ubuntu-latest`. Issue #12 has the reasoning for
    the move and this reversal; the pool being shared, not the mechanism, is what
    made it fail.

    Checked per job rather than as a whole-file substring search: the workflows hold
    four jobs across three files, and a search cannot tell whether one of them was
    missed."""
    seen = []
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text())
        for name, job in workflow["jobs"].items():
            seen.append(f"{path.name}:{name}")
            assert job["runs-on"] == EXPECTED_RUNNER, (
                f"{path.name}:{name} runs on {job['runs-on']!r}"
            )
    # Without this the test passes on a glob that matched nothing, which is exactly
    # how it behaves if the workflows are moved or renamed.
    assert len(seen) >= 4, f"found only {seen}; expected at least the four known jobs"


# The names in owasp_kb_cli.doctor.CHECKS. Duplicated here rather than imported:
# the CLI ships inside plugins/ and is not on the import path under bare pytest,
# which is what CI runs -- the same reason the other repository tooling in this
# file is loaded by path. A rename therefore has to be made in both places, which
# is the point: the docs are what a dev reads when a check fails.
DOCTOR_CHECK_NAMES = {
    "docker",
    "plugin",
    "pin",
    "image",
    "server",
    "hooks",
    "state",
    "ssh",
    "marketplace",
}


def test_the_doctor_check_names_are_the_ones_the_cli_registers():
    """Guard on the test below, which reads the docs against DOCTOR_CHECK_NAMES. If
    that set drifts from the CLI, the docs check passes while describing checks
    that do not exist -- documentation asserted against documentation."""
    text = Path("plugins/owasp-kb/bin/owasp_kb_cli/doctor.py").read_text()
    registry = text[text.index("CHECKS: list[") : text.index("def run(")]
    registered = set(re.findall(r'\("(\w+)", check_', registry))
    assert registered == DOCTOR_CHECK_NAMES, (
        f"doctor registers {sorted(registered)}, this file lists {sorted(DOCTOR_CHECK_NAMES)}"
    )


def test_the_troubleshooting_table_names_a_doctor_check_for_every_symptom():
    """The troubleshooting table is the reason doctor exists, so a check going
    missing from the docs must fail here rather than leaving a dev with output they
    cannot look up.

    Names in backticks, not prose: a table saying "run owasp-kb doctor" and nothing
    else is exactly what the table said before doctor existed."""
    text = Path("docs/install.md").read_text()
    table = "\n".join(line for line in text.splitlines() if line.startswith("|"))
    assert table, "docs/install.md has no table at all"
    assert "owasp-kb doctor" in table, "the troubleshooting table never mentions doctor"
    missing = {name for name in DOCTOR_CHECK_NAMES if f"`{name}`" not in table}
    assert not missing, (
        f"docs/install.md's troubleshooting table has no row naming doctor checks "
        f"{sorted(missing)}; a check whose output has no documented symptom is a "
        "check nobody will know how to act on"
    )


def _flagged_vulnerability_names() -> tuple[str, ...]:
    """The hook's firing vocabulary, imported from the plugin's own package.

    Not duplicated here: a second list is a second thing to forget, and the whole
    defect this guards against was two surfaces disagreeing about which
    vulnerability classes exist.
    """
    path = str(Path("plugins/owasp-kb/bin").resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    from owasp_kb_cli.security_terms import VULNERABILITY_NAMES

    return VULNERABILITY_NAMES


def test_every_flagged_vulnerability_is_advertised_by_the_tools():
    """The hook tells an agent to call owasp_search for a class the tool's own
    description does not mention. SSRF was absent from every discovery surface
    while the corpus carried a dedicated cheat sheet and ASVS V1.3.6, and nothing
    compared the two."""
    from owasp_kb.server.tools import TOOL_TRIGGER_TOPICS

    advertised = " ".join(TOOL_TRIGGER_TOPICS).lower()
    missing = [n for n in _flagged_vulnerability_names() if n.lower() not in advertised]
    assert not missing, (
        f"the hook flags {missing} and no tool description mentions them, so an "
        "agent sent to owasp_search meets a tool that does not claim the topic"
    )


def test_the_secure_coding_skill_claims_the_triage_moment():
    """It said "when writing or reviewing application code". The session that
    skipped it had written no code -- it was triaging an issue and planning a fix --
    so the description excluded the moment the skill was most needed."""
    when = _frontmatter(SKILLS_DIR / "owasp-secure-coding" / "SKILL.md")["description"].lower()
    for moment in ("triag", "planning", "diagnos"):
        assert moment in when, (
            f"the description does not claim to apply when {moment}...; an agent "
            "choosing an approach reads it as not yet applicable"
        )


@pytest.mark.parametrize("skill", ["owasp-secure-coding", "owasp-threat-model"])
def test_the_skill_descriptions_name_every_flagged_vulnerability(skill):
    """The hook and the skill must not drift: a class the hook flags and the skill
    does not name sends an agent to a skill that does not claim the topic."""
    described = _frontmatter(SKILLS_DIR / skill / "SKILL.md")["description"].lower()
    missing = [n for n in _flagged_vulnerability_names() if n.lower() not in described]
    assert not missing, f"{skill} does not name {missing}"


def test_the_secure_coding_body_says_what_recall_cannot_give():
    """The skill was declined for adding "no new insight", so the body leads with
    the two things the corpus provides that recall cannot -- a citable id, and an
    enumeration of what a fix must cover."""
    # Whitespace-normalised, as several tests in this file already are: both
    # phrases wrap across a line break, and where a hard wrap falls is not what
    # this test is about.
    body = " ".join((SKILLS_DIR / "owasp-secure-coding" / "SKILL.md").read_text().split())
    assert "cannot check that from the inside" in body
    assert "before choosing the approach" in body, (
        "a search run to confirm a chosen approach does not surface what the "
        "decision already excluded, which is how the observed gap survived"
    )


def _step_zero(skill: str) -> str:
    """The step 0 block of a fan-out skill's Process, up to where step 1 begins."""
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    _, _, after = body.partition("0. **Declare the stages")
    assert after, f"{skill} has no step 0: the run never states its plan"
    block, separator, _ = after.partition("\n1. **Agree the scope")
    assert separator, f"{skill} step 0 is not followed by step 1"
    return block


def _declared_stages(skill: str) -> list[str]:
    """The stage subjects from step 0's table, in document order."""
    return [
        row.group(1).strip()
        # The rows are indented: the table sits inside a numbered list item.
        for row in re.finditer(r"^\s*\|\s*\d\s*\|([^|]+)\|", _step_zero(skill), re.MULTILINE)
    ]


@pytest.mark.parametrize("skill", sorted(FAN_OUT_SKILLS))
def test_a_fan_out_skill_declares_its_stages_before_dispatching(skill):
    """A run of ~140 agents over several hours otherwise states its plan nowhere, so a
    skipped stage is noticeable only by what fails downstream -- which is why
    gate_triage_on_inventory.py had to exist."""
    assert _declared_stages(skill) == STAGES


def test_both_fan_out_skills_carry_the_identical_step_zero():
    """These two share ~450 lines and have already drifted by ~167. This pins the part being
    added, so an edit to one is an edit to both -- byte-for-byte, not just the stage names,
    which the test above already covers."""
    verify, gap_report = sorted(FAN_OUT_SKILLS)
    assert _step_zero(verify) == _step_zero(gap_report)


def test_only_the_probe_runner_holds_a_shell():
    """The grant must not spread. A verdict-forming agent with `Bash` bypasses
    block_excluded_reads.py entirely -- its matcher is Read|Grep|Glob, so `cat` is
    outside it, which is why the shell went to an agent that decides nothing."""
    with_shell = {n for n in EXPECTED_AGENTS if "Bash" in _agent(n)[0]["tools"]}
    assert with_shell == {"owasp-probe-runner"}


def test_the_probe_runner_holds_nothing_but_a_shell():
    """It runs a spec it was handed. Read, Grep or Glob would let it go looking, and
    looking is what the exclusion control governs."""
    meta, _ = _agent("owasp-probe-runner")
    assert [t.strip() for t in meta["tools"].split(",")] == ["Bash"]


def test_the_probe_runner_is_given_no_exclusion_list():
    """The counterpart to test_every_reading_agent_carries_the_exclusion_rule: this
    one must NOT carry it. Naming the paths to the agent that could open them is the
    thing the vetting step exists to avoid."""
    _, body = _agent("owasp-probe-runner")
    assert "EXCLUDED" not in body


@pytest.mark.parametrize(
    "clause",
    [
        "sessions/$CLAUDE_CODE_SESSION_ID/probes",
        "never write inside the target",
        "never modify",
        "loopback",
        "not runnable",
    ],
    ids=["scratch-dir", "no-target-writes", "no-mutation", "loopback-only", "declines"],
)
def test_the_probe_runner_carries_the_sandbox_contract(clause):
    """Nothing enforces this contract -- a hook on Bash cannot be scoped to one agent,
    since PreToolUse payloads carry no agent identity. The prompt is the whole control,
    so its clauses are pinned here."""
    _, body = _agent("owasp-probe-runner")
    assert clause in body


def test_the_finder_offers_a_probe_when_a_claim_is_executable():
    """A claim settled by running something should ship the recipe. The finder cannot
    run it -- it holds no shell by design -- so the spec travels to the orchestrator,
    which dispatches the runner."""
    _, body = _agent("owasp-requirement-finder")
    assert "probe" in body.lower()
    for part in ("build", "run", "observe", "falsify"):
        assert f'"{part}"' in body, f"the probe spec must name its {part} part"
