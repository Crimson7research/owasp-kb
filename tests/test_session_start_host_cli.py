"""The SessionStart hook that states where the host CLI lives.

The harness gives an agent no way to learn this path: CLAUDE_PLUGIN_ROOT is set
for a hook process and not for a Bash tool call, so the process that can resolve
the directory is the one that has to say it. What these pin is that the note
carries an absolute path and names the commands -- a wording edit that drops
either is silent, because the hook still fires and still emits valid JSON.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HOOK = Path("plugins/owasp-kb/hooks/state_host_cli.py")
SCRIPTS = Path("plugins/owasp-kb/scripts")


def _run(stdin: str = "{}", env: dict[str, str] | None = None) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, f"hook must never fail the call: {result.stderr}"
    return result.returncode, result.stdout


def _context(stdin: str = "{}") -> str:
    _, out = _run(stdin)
    return json.loads(out)["hookSpecificOutput"]["additionalContext"]


def test_it_emits_one_session_start_context_block():
    code, out = _run(json.dumps({"session_id": "sess-1", "source": "startup"}))
    assert code == 0
    payload = json.loads(out)
    assert set(payload) == {"hookSpecificOutput"}, (
        "Claude Code reads both `additional_context` and `hookSpecificOutput` "
        "without deduplicating them, so a hook emits exactly one of the two"
    )
    block = payload["hookSpecificOutput"]
    assert block["hookEventName"] == "SessionStart"
    assert block["additionalContext"].strip()


def test_the_note_states_an_absolute_scripts_directory():
    """A relative path is the whole defect: the agent's working directory is the
    target repository, not the plugin, so `scripts/owasp-kb` resolves to nothing.
    """
    note = _context()
    expected = str(SCRIPTS.resolve())
    assert expected in note, f"the note does not name {expected}"
    assert expected.startswith("/"), "the fixture itself is not absolute; the test is wrong"


def test_the_note_says_the_tools_are_not_on_path_and_shows_the_invocation():
    """Naming the directory is not enough. An agent that reads a path and types a
    bare name still gets command-not-found, so the note states the route."""
    note = _context()
    assert "not on PATH" in note
    assert f"python3 {SCRIPTS.resolve()}/owasp-kb" in note, (
        "the note never shows the actual invocation, so the path is left as an exercise"
    )


def test_the_note_names_every_command_the_cli_registers():
    """Imported from the entry point rather than duplicated: a second list is a
    second thing to forget, and a note advertising a command the CLI dropped is
    worse than one that lists none."""
    # Anchored on "= sub.add_parser(" rather than the bare substring
    # "sub.add_parser(": the CLI nests a second layer of subparsers under
    # `report` and `sessions` (`r_sub.add_parser("merge", ...)`,
    # `s_sub.add_parser("list"/"purge", ...)`), and the bare substring matches
    # those too, since "r_sub.add_parser(" contains "sub.add_parser(" as a
    # substring. This hook advertises top-level commands, not their
    # subcommands, so the filter has to say "sub" the variable, not "sub" the
    # tail of some other name.
    import re

    source = (SCRIPTS / "owasp-kb").read_text()
    registered = {
        line.split('"')[1]
        for line in source.splitlines()
        if re.search(r"=\s*sub\.add_parser\(", line)
    }
    assert registered == {"report", "doctor", "sessions"}, (
        f"the CLI registers {sorted(registered)}; this test's expectation is stale"
    )
    note = _context()
    missing = {name for name in registered if name not in note}
    assert not missing, f"the note never names {sorted(missing)}"


def test_it_honours_claude_plugin_root_when_the_harness_sets_it():
    """The installed copy is a cache directory, not this checkout. Deriving from
    __file__ is the fallback; the variable is the answer when it is present."""
    import os

    env = dict(os.environ, CLAUDE_PLUGIN_ROOT="/somewhere/else/owasp-kb")
    _, out = _run("{}", env=env)
    note = json.loads(out)["hookSpecificOutput"]["additionalContext"]
    assert "/somewhere/else/owasp-kb/scripts" in note


def test_it_fails_open_and_never_blocks_a_session_start():
    """Failing closed would break session startup over a path note. The degraded
    state is the behaviour the plugin had before this hook, which is survivable --
    so any exception exits 0. The exit code is asserted by _run.

    Emission is deliberately not required: the contract is "exits 0 and emits
    nothing", so an edit making stdin load-bearing may legitimately fall silent.
    """
    _, out = _run("not json at all {{{")
    if out.strip():
        assert json.loads(out)["hookSpecificOutput"]["hookEventName"] == "SessionStart"
