"""Tests for the plugin's host-side CLI.

The CLI runs on the host rather than as an MCP tool: the server's state mount is
read-only and the target repository is not mounted at all, so nothing inside the
container can write a report or clear a session.

`plugins/owasp-kb/bin` is put on the path and the package imported normally, rather
than loading each module by file path. The modules import each other as
`from owasp_kb_cli.state import ...`, and loading a submodule by path without its
parent package registered breaks that import -- so a path-loading helper would test
something that cannot run.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

BIN = Path("plugins/owasp-kb/bin")


def _module(name: str):
    path = str(BIN.resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module(f"owasp_kb_cli.{name}")


def test_state_dir_honours_the_config_dir_override(monkeypatch, tmp_path):
    """The .mcp.json wrapper, both hooks and the skills all resolve this path
    independently. The CLI has to agree with them, or it reports on a directory
    nothing writes to."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    state = _module("state")
    assert state.state_dir() == tmp_path / "owasp-kb"


def test_state_dir_falls_back_to_the_home_default(monkeypatch, tmp_path):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    state = _module("state")
    assert state.state_dir() == tmp_path / ".claude" / "owasp-kb"


def test_the_resolved_path_matches_the_one_the_server_wrapper_creates():
    """The CLI and the .mcp.json wrapper must name the same directory. They are
    written in different languages in different files, so nothing else compares
    them -- and a disagreement means `sessions list` reports an empty directory
    while an assessment writes to another one."""
    monkeypatch_free = _module("state")
    wrapper = Path("plugins/owasp-kb/.mcp.json").read_text()
    assert "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb" in wrapper, (
        "the wrapper no longer builds the path this module reproduces"
    )
    assert monkeypatch_free.state_dir().name == "owasp-kb"
    assert monkeypatch_free.state_dir().parent.name == ".claude"


@pytest.mark.parametrize("bad", ["../../etc", "a/b", "..", "/absolute", "", ".", "a/../b"])
def test_validate_session_id_refuses_anything_that_could_escape(bad):
    """`purge` deletes a directory tree. A session id reaches this CLI from an
    agent's shell command, so `purge ../../..` must be refused here rather than
    sanitised somewhere downstream."""
    state = _module("state")
    with pytest.raises(ValueError):
        state.validate_session_id(bad)


def test_validate_session_id_accepts_a_real_session_id():
    """Guard on the test above: it passes just as well against a validator that
    rejects everything, which would leave purge unusable and the suite green."""
    state = _module("state")
    assert state.validate_session_id("1bba9a82-7978-4f47-8e28-6c3640b7c8f8")


def test_session_dir_refuses_a_traversal_id_too(monkeypatch, tmp_path):
    """The validator is only a control where it is actually called. session_dir is
    what every caller uses to build a path, so it validates rather than trusting
    its caller to have done so."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    state = _module("state")
    with pytest.raises(ValueError):
        state.session_dir("../escape")
