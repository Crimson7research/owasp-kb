"""Validate packaging manifests and skill frontmatter."""

from __future__ import annotations

import json
import re
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
    assert data["version"]
    assert data["license"] == "MIT"


def test_plugin_declares_its_mcp_config():
    """Installing the plugin must also wire up the server; otherwise the skills
    reference tools that do not exist."""
    data = json.loads(PLUGIN.read_text())
    assert data["mcpServers"] == "./.mcp.json"
    assert MCP_CONFIG.exists()


SERVER_WRAPPER = Path("plugins/owasp-kb/bin/owasp-kb-server")


def test_mcp_config_starts_the_server_through_the_wrapper():
    """The docker invocation moved into a wrapper so the state directory can be
    mounted with a path only a shell can resolve. The wrapper resolves by name
    from the plugin's bin/, which Claude Code puts on PATH -- rather than by
    ${...} expansion inside .mcp.json, which no installed plugin relies on and
    which would fail silently if unsupported."""
    server = json.loads(MCP_CONFIG.read_text())["mcpServers"]["owasp-kb"]
    assert server["command"] == "owasp-kb-server"
    assert SERVER_WRAPPER.is_file()
    assert SERVER_WRAPPER.stat().st_mode & 0o111, "wrapper is not executable"


def test_the_server_wrapper_runs_the_container_without_network():
    """The property the old assertion protected, checked where it now lives."""
    script = SERVER_WRAPPER.read_text()
    assert "--network none" in script
    assert "docker run -i --rm" in script.replace("\\\n", "").replace("\n", " ")


def test_the_state_mount_is_read_only():
    """The image gains read access to one directory and no write access at all.
    The server reads the exclusion list and the findings an agent wrote; it never
    writes there, and a read-only mount also sidesteps the uid mismatch -- the
    container runs as 10001 and the directory belongs to the host user."""
    script = SERVER_WRAPPER.read_text()
    assert ":/state:ro" in script, "the state mount must be read-only"
    assert ':/state"' not in script, "a writable state mount would let the image modify the host"


def test_the_wrapper_creates_the_state_directory_itself():
    """A bind mount whose source is missing is created by the docker daemon and
    owned by root, which the agent then cannot write to."""
    assert "mkdir -p" in SERVER_WRAPPER.read_text()


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
    body = (SKILLS_DIR / skill / "SKILL.md").read_text()
    assert "Show the remediation as a snippet" in body
    assert "no snippet is offered" in body, (
        "the architectural exception must be stated, or an agent cannot tell a "
        "considered omission from a forgotten one"
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
}

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


def test_all_five_agents_exist():
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
    """Every role reads and reports. None edits the target codebase."""
    meta, _ = _agent(name)
    tools = meta["tools"]
    assert "Write" not in tools
    assert "Edit" not in tools


@pytest.mark.parametrize("name", sorted(EXPECTED_AGENTS))
def test_every_agent_carries_the_exclusion_rule(name):
    """A prior assessment in the target is another agent's conclusion. Every role
    that reads the codebase can stumble on one -- the verifiers did."""
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


def test_verify_skill_documents_the_uncertain_verdicts():
    """A report that cannot say 'I could not determine this' says PASS instead."""
    body = (SKILLS_DIR / "owasp-asvs-verify" / "SKILL.md").read_text()
    for verdict in ("N/A (unverified)", "INSUFFICIENT EVIDENCE", "GAP (unconfirmed)"):
        assert verdict in body


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


def test_gap_report_carries_the_uncertain_verdicts_through():
    """Collapsing them into MET or GAP would hide exactly what fan-out buys."""
    body = (SKILLS_DIR / "owasp-asvs-gap-report" / "SKILL.md").read_text()
    for verdict in ("N/A (unverified)", "INSUFFICIENT EVIDENCE", "GAP (unconfirmed)"):
        assert verdict in body


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


def test_one_version_governs_the_package_the_plugin_and_the_marketplace():
    """Three version numbers disagreed -- pyproject 0.1.0, marketplace 0.3.0,
    plugin 0.8.0 -- and nothing compared them. A reader could not tell which
    described the thing they were running. See #13."""
    from owasp_kb import __version__

    plugin = json.loads(PLUGIN.read_text())["version"]
    marketplace = json.loads(MARKETPLACE.read_text())["plugins"][0]["version"]
    assert plugin == __version__, f"plugin.json {plugin} != owasp_kb {__version__}"
    assert marketplace == __version__, f"marketplace {marketplace} != owasp_kb {__version__}"


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
    text = Path("LICENSE-CWE").read_text()
    assert "CWE" in text
    assert len(text) > 500, "a stub is not the terms"


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


EXPECTED_LICENSE_NAMES = {"LICENSE", "LICENSE-DATA", "LICENSE-CWE", "NOTICE"}
EXPECTED_LICENSES_LABEL = "MIT AND CC-BY-SA-4.0 AND LicenseRef-CWE-TOU"


@pytest.mark.parametrize("target_name", ["lite", "full"])
def test_the_dockerfile_ships_every_license_text(target_name):
    """The image shipped an OCI label and no notice. docs/licensing.md asks a
    redistributor to keep LICENSE-DATA with the artifact; the image did not.
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
    copied_names = set(tokens[1:-1])
    assert copied_names == EXPECTED_LICENSE_NAMES, (
        f"{target_name}: COPY names {copied_names}, expected {EXPECTED_LICENSE_NAMES}"
    )

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


NOTICE_FILE = Path("NOTICE")
LOCK_FILE = Path("sources.lock.yml")


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


def _lock_packs() -> dict:
    return yaml.safe_load(LOCK_FILE.read_text())["packs"]


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
