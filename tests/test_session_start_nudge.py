"""The SessionStart hook that argues the token ledger for owasp-secure-coding.

Unlike the other three hooks this one is unconditional -- nothing arms it and no
vocabulary gates it -- so what these pin is the payload's content rather than its
firing conditions. A wording edit that drops a load-bearing part is the failure
mode, and it is silent: the hook still fires, still emits valid JSON, and says
less.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HOOK = Path("plugins/owasp-kb/hooks/nudge_secure_coding.py")


def _run(stdin: str = "{}") -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=stdin,
        capture_output=True,
        text=True,
    )
    # Asserted here, with stderr, so a crash reports its traceback rather than a
    # bare `assert 1 == 0`. Matches tests/test_exclusion_hook.py and
    # tests/test_inventory_gate.py.
    assert result.returncode == 0, f"hook must never fail the call: {result.stderr}"
    return result.returncode, result.stdout


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


def test_it_fails_open_and_never_blocks_a_session_start():
    """A hook failing closed would break session startup over a reminder. The
    degraded state here is exactly the behaviour the plugin had before this hook
    existed, which is recognisable and survivable -- so any exception exits 0.

    Nothing in the payload is consulted today, so garbage stdin cannot currently
    reach the handler, and the hook emits its block regardless. This pins the
    direction anyway: the handler is what a later edit that does consult stdin will
    land behind.

    What is pinned is the exit code, plus the rule that whatever reaches stdout is
    parseable. Emission is deliberately not required: the contract is "exits 0 and
    emits nothing", so an edit that makes stdin load-bearing may legitimately fall
    silent here. Requiring the block would fail that correct behaviour and would
    make this a test of emission rather than of direction. The exit code itself is
    asserted by _run, with stderr, so it is not repeated here.
    """
    _, out = _run("not json at all {{{")
    if out.strip():
        assert json.loads(out)["hookSpecificOutput"]["hookEventName"] == "SessionStart"
