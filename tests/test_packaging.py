"""Validate packaging manifests and skill frontmatter."""

from __future__ import annotations

import json
import re
from pathlib import Path

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


def test_mcp_config_runs_the_container_without_network():
    data = json.loads(MCP_CONFIG.read_text())
    server = data["mcpServers"]["owasp-kb"]
    assert server["command"] == "docker"
    args = server["args"]
    assert "-i" in args, "stdio transport requires -i"
    assert "--rm" in args
    assert args[args.index("--network") + 1] == "none"


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
    referenced = set(re.findall(r"\b(owasp_\w+|kb_info)\b", body))
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
