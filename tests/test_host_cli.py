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


def test_the_check_registry_is_populated_and_callable():
    """Guard on every doctor test below: they drive run() with injected checks, so
    an empty or malformed CHECKS list would leave the real doctor untested while
    the suite stayed green."""
    doctor = _module("doctor")
    assert doctor.CHECKS, "the check registry is empty, so the real doctor checks nothing"
    for name, check in doctor.CHECKS:
        assert name, "a check with no name cannot be reported"
        assert callable(check)


def test_run_exits_non_zero_when_a_check_fails():
    """Injected rather than provoked: the real checks need docker, a registry and
    an installed plugin, and a doctor that always exited 0 would pass a suite that
    only ever ran it on a healthy machine."""
    doctor = _module("doctor")
    ok = ("fine", lambda: doctor.Result(True, "all good"))
    bad = ("broken", lambda: doctor.Result(False, "it is broken", remedy="run something"))
    assert doctor.run([ok]) == 0
    assert doctor.run([ok, bad]) == 1


def test_a_failing_check_prints_its_remedy(capsys):
    """A check that reports a failure and not what to do about it is a support
    ticket with extra steps."""
    doctor = _module("doctor")
    bad = ("broken", lambda: doctor.Result(False, "it is broken", remedy="run something"))
    doctor.run([bad])
    printed = capsys.readouterr()
    assert "run something" in printed.out + printed.err


def test_a_check_that_raises_is_reported_as_a_failure_not_a_crash():
    """doctor runs on a machine that is by definition misconfigured. A check that
    raises must not take the other eight with it, or the first problem hides
    every other one."""
    doctor = _module("doctor")

    def explode():
        raise OSError("no docker socket")

    assert doctor.run([("explodes", explode)]) == 1


def test_the_hooks_check_states_that_it_cannot_see_harness_registration():
    """It can verify the files and not that Claude Code registered them. A check
    implying otherwise is the "true about the wrong thing" failure this repository
    keeps paying for, so the limit goes in the output rather than only in the
    docs."""
    doctor = _module("doctor")
    names = dict(doctor.CHECKS)
    assert "hooks" in names
    result = names["hooks"]()
    assert "registered" in result.detail.lower()


def test_the_pin_check_rejects_a_tag_and_accepts_a_digest(monkeypatch, tmp_path):
    """The whole point of the pin, checked on a dev's machine rather than only in
    CI: a tag is shadowed by any local image of that name."""
    doctor = _module("doctor")
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text('{"name": "owasp-kb"}')
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    monkeypatch.delenv("OWASP_KB_IMAGE", raising=False)

    (root / ".mcp.json").write_text('{"a": "${OWASP_KB_IMAGE:-ghcr.io/x/owasp-kb:full}"}')
    assert doctor.check_image_pinned().ok is False

    digest = "ghcr.io/x/owasp-kb@sha256:" + "a" * 64
    (root / ".mcp.json").write_text('{"a": "${OWASP_KB_IMAGE:-' + digest + '}"}')
    assert doctor.check_image_pinned().ok is True


def test_the_plugin_check_fails_when_a_version_field_reappears(monkeypatch, tmp_path):
    """The repository test catches this before merge; doctor catches an installed
    copy that predates the change, where the symptom is an update that silently
    does nothing."""
    doctor = _module("doctor")
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))

    (root / ".claude-plugin" / "plugin.json").write_text('{"name": "owasp-kb"}')
    assert doctor.check_plugin_identity().ok is True

    (root / ".claude-plugin" / "plugin.json").write_text('{"name": "owasp-kb", "version": "1.0.0"}')
    result = doctor.check_plugin_identity()
    assert result.ok is False
    assert "1.0.0" in result.detail
