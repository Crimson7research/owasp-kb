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
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BIN = Path("plugins/owasp-kb/bin")
HOOK = Path("plugins/owasp-kb/hooks/flag_security_topic.py")


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


def _seed_session(root: Path, session: str, findings: int = 2, sections: int = 3) -> Path:
    directory = root / "owasp-kb" / "sessions" / session
    (directory / "report").mkdir(parents=True)
    lines = "\n".join(f'{{"req_id": "V1.1.{n}", "verdict": "MET"}}' for n in range(findings))
    (directory / "findings.jsonl").write_text(lines + "\n")
    (directory / "inventory.md").write_text("# inventory\n")
    for n in range(sections):
        (directory / "report" / f"{100 + n}_section.md").write_text("body\n")
    return directory


def test_summarise_counts_what_a_session_holds(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    _seed_session(tmp_path, "abc123", findings=4, sections=2)
    summary = sessions.summarise(tmp_path / "owasp-kb" / "sessions" / "abc123")
    assert summary.findings == 4
    assert summary.sections == 2
    assert summary.has_inventory is True
    assert summary.bytes > 0


def test_the_summary_carries_no_field_that_could_identify_a_target(monkeypatch, tmp_path):
    """Target identity was deliberately removed from recorded state. A listing tool
    that recovered it would undo that.

    Pinned as an exact field set rather than a search for suspicious strings: a
    substring check passes on anything it did not think to look for, and the
    failure mode here is a *new field* -- a repo name, a path, a first finding's
    excerpt -- added because it seemed helpful. Adding one has to fail here and be
    argued for rather than slipping through.
    """
    import dataclasses

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    _seed_session(tmp_path, "abc123")
    summary = sessions.summarise(tmp_path / "owasp-kb" / "sessions" / "abc123")
    assert {f.name for f in dataclasses.fields(summary)} == {
        "session",
        "mtime",
        "findings",
        "sections",
        "has_inventory",
        "bytes",
        "path",
    }


def test_list_sessions_returns_every_session(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    _seed_session(tmp_path, "aaa")
    _seed_session(tmp_path, "bbb")
    assert {s.session for s in sessions.list_sessions()} == {"aaa", "bbb"}


def test_list_sessions_is_empty_rather_than_failing_when_nothing_exists(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    assert sessions.list_sessions() == []


def test_purge_requires_confirmation(monkeypatch, tmp_path):
    """It deletes an engagement's accumulated findings. A flag typo must not."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    directory = _seed_session(tmp_path, "aaa")
    assert sessions.purge(["aaa"], confirmed=False) == 1
    assert directory.is_dir(), "purge deleted without confirmation"


def test_purge_deletes_only_the_named_session(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    doomed = _seed_session(tmp_path, "aaa")
    kept = _seed_session(tmp_path, "bbb")
    assert sessions.purge(["aaa"], confirmed=True) == 0
    assert not doomed.exists()
    assert kept.is_dir()


@pytest.mark.parametrize("bad", ["../../etc", "a/b", ".."])
def test_purge_refuses_a_traversal_id(monkeypatch, tmp_path, bad):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    outside = tmp_path / "owasp-kb" / "sentinel"
    outside.mkdir(parents=True)
    assert sessions.purge([bad], confirmed=True) == 1
    assert outside.is_dir()


def test_purge_refuses_a_session_that_does_not_exist(monkeypatch, tmp_path):
    """Otherwise a typo reports success and the operator believes the material is
    gone when it is still there."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    assert sessions.purge(["nope"], confirmed=True) == 1


def test_purge_deletes_nothing_when_one_of_several_ids_is_bad(monkeypatch, tmp_path):
    """All-or-nothing. A partial purge across a batch leaves the operator with no
    idea which sessions survived."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    real = _seed_session(tmp_path, "aaa")
    assert sessions.purge(["aaa", "nope"], confirmed=True) == 1
    assert real.is_dir()


def test_older_than_selects_by_mtime(monkeypatch, tmp_path):
    import os as _os
    import time as _time

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    sessions = _module("sessions")
    old = _seed_session(tmp_path, "old")
    _seed_session(tmp_path, "new")
    long_ago = _time.time() - 60 * 60 * 24 * 90
    _os.utime(old, (long_ago, long_ago))
    assert [s.session for s in sessions.older_than(30)] == ["old"]


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


AUTH_OK = "Hi someone! You've successfully authenticated, but GitHub does not provide shell access."
NO_AGENT = "Could not open a connection to your authentication agent."


def test_the_ssh_check_passes_when_authentication_works_with_no_agent(monkeypatch):
    """This check asserted that `ssh-add -l` succeeds, and reported a failure on a
    machine where the marketplace clone had just worked -- a passphraseless key at a
    default path authenticates with no agent running at all. Observed directly:
    `ssh-add -l` exited 2 with "Could not open a connection to your authentication
    agent" while `ssh -T git@github.com` answered "successfully authenticated".

    A check that reports a problem which is not one is worse than no check: it
    teaches people to ignore the output. So it tests authentication, which is the
    thing that matters, and treats the agent as a diagnosis for a failure rather
    than a requirement.
    """
    doctor = _module("doctor")

    def fake(*cmd):
        if cmd[0] == "ssh":
            return _FakeProc(1, "", AUTH_OK)
        if cmd[0] == "ssh-add":
            return _FakeProc(2, "", NO_AGENT)
        return _FakeProc(0)

    monkeypatch.setattr(doctor, "_run", fake)
    result = doctor.check_ssh_prerequisites()
    assert result.ok is True, result.detail


def test_the_ssh_check_blames_the_agent_only_when_authentication_failed(monkeypatch):
    """The diagnosis still has to happen -- an unloaded key is a real cause, and
    Claude Code suppresses the passphrase prompt so it surfaces as an unexplained
    clone failure. It just must not fire when nothing is wrong."""
    doctor = _module("doctor")

    def fake(*cmd):
        if cmd[0] == "ssh":
            return _FakeProc(255, "", "git@github.com: Permission denied (publickey).")
        if cmd[0] == "ssh-keygen":
            return _FakeProc(0, "github.com ssh-ed25519 AAAA...")
        if cmd[0] == "ssh-add":
            return _FakeProc(2, "", NO_AGENT)
        return _FakeProc(0)

    monkeypatch.setattr(doctor, "_run", fake)
    result = doctor.check_ssh_prerequisites()
    assert result.ok is False
    assert "ssh-agent" in result.detail


def test_the_ssh_check_blames_known_hosts_before_the_agent(monkeypatch):
    """An unknown host fails earlier than a missing key and has a different fix, so
    reporting the agent for it would send a dev down the wrong path."""
    doctor = _module("doctor")

    def fake(*cmd):
        if cmd[0] == "ssh":
            return _FakeProc(255, "", "Host key verification failed.")
        if cmd[0] == "ssh-keygen":
            return _FakeProc(1, "", "")
        return _FakeProc(0)

    monkeypatch.setattr(doctor, "_run", fake)
    result = doctor.check_ssh_prerequisites()
    assert result.ok is False
    assert "known_hosts" in result.detail


def test_the_vocabulary_holds_only_unambiguous_vulnerability_names():
    """Ambiguous nouns are excluded on purpose. `token`, `session`, `cookie` and
    `logging` appear constantly in ordinary development conversation -- a hook
    firing on most prompts becomes wallpaper, which is how a false-positive check
    taught people to ignore `owasp-kb doctor`'s output. Precision is chosen over
    recall here, and the reworded skill descriptions are what cover
    vaguely-worded security work."""
    terms = _module("security_terms")
    names = {n.lower() for n in terms.VULNERABILITY_NAMES}
    assert "ssrf" in names, "SSRF is the class this whole change exists for"
    for ambiguous in ("token", "session", "cookie", "auth", "crypto", "logging"):
        assert ambiguous not in names, (
            f"{ambiguous!r} is in the firing vocabulary; it appears in ordinary "
            "development conversation and would make the hook fire on most prompts"
        )


def test_every_vocabulary_term_compiles_into_the_matcher():
    """The list is only a control if the pattern built from it actually matches. A
    term with a regex metacharacter that was never escaped would silently never
    fire."""
    terms = _module("security_terms")
    for name in terms.VULNERABILITY_NAMES:
        assert terms.matched_term(f"please look at this {name} problem") is not None, (
            f"{name!r} is in the vocabulary and does not match its own name"
        )


def test_the_matcher_ignores_a_prompt_with_no_vulnerability_name():
    terms = _module("security_terms")
    assert terms.matched_term("refactor the session token cookie cache") is None


def test_the_matcher_is_word_bounded():
    """Without \\b, `XSS` matches inside an unrelated identifier and the hook fires
    on prompts that have nothing to do with security."""
    terms = _module("security_terms")
    assert terms.matched_term("the maXSSive refactor") is None
    assert terms.matched_term("fix the XSS bug") == "XSS"


def test_a_cve_id_counts_as_naming_a_vulnerability():
    """A CVE id names a specific vulnerability without naming its class, and
    carries the same problem: you cannot tell from the inside whether you recall
    it accurately."""
    terms = _module("security_terms")
    assert terms.matched_term("patch CVE-2024-3094 today") == "CVE-2024-3094"


def _run_hook(payload: dict, config_dir: Path, raw: str | None = None):
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload) if raw is None else raw,
        capture_output=True,
        text=True,
        env={**os.environ, "CLAUDE_CONFIG_DIR": str(config_dir)},
    )


def test_the_hook_injects_context_when_a_vulnerability_is_named(tmp_path):
    result = _run_hook({"session_id": "s1", "prompt": "investigate the SSRF report"}, tmp_path)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "UserPromptSubmit"
    assert "SSRF" in out["additionalContext"]
    assert "owasp_search" in out["additionalContext"]


def test_the_hook_stays_silent_on_an_ordinary_prompt(tmp_path):
    """The false-positive rule, and the reason anyone will read the output."""
    result = _run_hook({"session_id": "s1", "prompt": "rename the session token helper"}, tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_the_hook_fires_once_per_session(tmp_path):
    """Repeating changes nothing: after one nudge the agent has either acted or
    decided not to, and a hook that repeats becomes wallpaper."""
    first = _run_hook({"session_id": "s1", "prompt": "an XXE issue"}, tmp_path)
    second = _run_hook({"session_id": "s1", "prompt": "another XXE issue"}, tmp_path)
    assert first.stdout.strip() != ""
    assert second.stdout.strip() == ""


def test_a_different_session_is_flagged_independently(tmp_path):
    """Guard on the test above: suppression keyed too broadly would silence every
    later session, which is indistinguishable from the hook being broken."""
    _run_hook({"session_id": "s1", "prompt": "an XXE issue"}, tmp_path)
    other = _run_hook({"session_id": "s2", "prompt": "an XXE issue"}, tmp_path)
    assert other.stdout.strip() != ""


@pytest.mark.parametrize("raw", ["", "not json at all", "[]", '{"prompt": null}'])
def test_the_hook_fails_open_on_unusable_input(tmp_path, raw):
    """It guards a reminder. A hook failing closed breaks unrelated sessions on a
    bug of its own -- ADR 0012 -- and the degraded state here is exactly the
    behaviour before it existed."""
    result = _run_hook({}, tmp_path, raw=raw)
    assert result.returncode == 0, f"non-zero exit on {raw!r}: {result.stderr}"
    assert result.stdout.strip() == "", f"emitted output on {raw!r}"


def test_the_hook_refuses_a_session_id_that_could_escape_the_state_tree(tmp_path):
    """The id reaches the hook from a payload and is used to build a path that gets
    written to. state.session_dir validates, so this must fail open rather than
    writing outside the tree."""
    result = _run_hook({"session_id": "../escape", "prompt": "an SSRF bug"}, tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == ""
    assert not (tmp_path / "escape").exists()


def test_the_hook_makes_the_cost_argument_rather_than_asserting_value(tmp_path):
    """The agent that skipped the corpus said it would add "process overhead
    without new insight". The payload has to answer that claim -- an unverifiable
    prediction and asymmetric costs -- not restate that the corpus is good."""
    result = _run_hook({"session_id": "s1", "prompt": "an IDOR bug"}, tmp_path)
    context = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "from the inside" in context, "does not name the unverifiable prediction"
    assert "not symmetric" in context, "does not make the cost argument"
    assert "from memory" in context, "does not require the omission to be stated"
    assert "before deciding the approach" in context, (
        "does not require the call to precede the decision; a session that searches "
        "to confirm a chosen approach keeps its blind spot"
    )


def test_the_hook_denies_the_framing_exemption_and_demands_precedence(tmp_path):
    """A second session declined the corpus for a different reason: the issue never said
    security, so it classified the work as a refactor and moved on. The payload has to
    refuse that inference, and it has to say the thing the corpus itself cannot -- that
    the control may already exist in this codebase. The figures are the argument: an
    unquantified claim that checking is cheap was already there and was declined."""
    result = _run_hook({"session_id": "s1", "prompt": "an SSRF bug"}, tmp_path)
    context = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"].lower()
    assert (
        "absence of security framing in the request is not evidence of absence of "
        "security relevance" in context
    ), "the framing exemption is not refused, or is refused inside a frame that grants it"
    assert "six minutes" in context, "the measured cost of checking is missing"
    assert "check whether this codebase already has the control before you design one" in context, (
        "precedence is not demanded as an instruction"
    )
    assert "grep for the control names the guidance uses" in context, (
        "the agent is told to grep but not what to grep for, which is the part the corpus supplies"
    )


def test_the_hook_fails_open_on_an_unusable_state_directory(tmp_path):
    """The fail-open claim has to hold for more than ValueError, and every other
    input in this file raises either ValueError or nothing: json.JSONDecodeError
    subclasses ValueError, and validate_session_id raises it too. So narrowing the
    handler to `except ValueError` passed the whole suite.

    A CLAUDE_CONFIG_DIR that is a regular file makes mkdir raise NotADirectoryError
    -- an OSError -- which is the class of failure the breadth exists for: an
    unwritable state tree, or an import that does not resolve."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("this is a file where a directory is needed\n")
    result = _run_hook({"session_id": "s1", "prompt": "an SSRF bug"}, blocker)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""
