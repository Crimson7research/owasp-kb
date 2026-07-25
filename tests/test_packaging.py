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
