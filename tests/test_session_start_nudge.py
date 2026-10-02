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


def _payload() -> str:
    """The constant itself, imported rather than re-run through the subprocess.

    Loaded by path because the hook is not part of any importable package -- the
    same reason tests/test_host_cli.py inserts plugins/owasp-kb/scripts on sys.path.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("nudge_secure_coding", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.NUDGE


def _router_terms() -> tuple[str, ...]:
    """The prompt router's vocabulary, imported from the plugin package."""
    path = str(Path("plugins/owasp-kb/scripts").resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    from owasp_kb_cli.security_terms import VULNERABILITY_NAMES

    return VULNERABILITY_NAMES


def test_the_payload_does_not_front_load_prompt_router_vocabulary():
    """SessionStart runs unconditionally, so it must not inject router terms.

    The separate UserPromptSubmit hook can still react when a user supplies one of
    these terms. Keeping the list imported avoids a second vocabulary that drifts.
    """
    payload = _payload().lower()
    present = [term for term in _router_terms() if term.lower() in payload]
    assert not present, f"SessionStart payload front-loads prompt router terms: {present}"


def test_the_payload_asks_for_both_notices():
    """The activation notice is c7-marketplace ADR 0012's: a skill that triggered
    and was ignored otherwise leaves the same transcript as one that never
    triggered.

    The decline notice is the half that ADR does not cover, and it exists in this
    payload and nowhere else -- SKILL.md is unreachable to an agent that decided
    against the skill, so an instruction placed there covers activations only.
    Losing it to a wording edit would be silent.
    """
    payload = _payload()
    assert "owasp-secure-coding" in payload
    assert "Using owasp-secure-coding to" in payload
    assert "Not using owasp-secure-coding:" in payload


def test_the_payload_argues_cost_rather_than_importance():
    """c7-marketplace ADR 0010 refuses exhortation and admits reference content on
    economics. Rewritten as "security is important", this hook stops being
    admissible under the decision that permitted it."""
    payload = _payload().lower()
    assert "input tokens" in payload
    assert "output tokens" in payload


def test_the_plugin_registers_the_hook_at_the_events_that_keep_it_resident():
    """A renamed hook script that silently stops firing looks identical to a plugin
    that was never installed, so the path is asserted to resolve.

    `resume` is excluded on purpose: a resumed session still holds the injection
    from its original start. `compact` is not -- a hook firing only at startup
    loses its context at the first compaction of a long session, which is the whole
    reason this is a SessionStart hook rather than a one-off note.
    """
    plugin = json.loads(Path("plugins/owasp-kb/.claude-plugin/plugin.json").read_text())
    entries = plugin["hooks"]["SessionStart"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["matcher"] == "startup|clear|compact"
    command = entry["hooks"][0]["command"]
    assert "nudge_secure_coding.py" in command
    assert HOOK.exists()
