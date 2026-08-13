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
    same reason tests/test_host_cli.py inserts plugins/owasp-kb/bin on sys.path.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("nudge_secure_coding", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.NUDGE


def _flagged_vulnerability_names() -> tuple[str, ...]:
    """The hook's firing vocabulary, imported from the plugin's own package.

    Not duplicated here: a second list is a second thing to forget, and the whole
    defect this guards against was two surfaces disagreeing about which
    vulnerability classes exist. The loader is repeated from tests/test_packaging.py
    -- the list it returns is not.
    """
    path = str(Path("plugins/owasp-kb/bin").resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    from owasp_kb_cli.security_terms import VULNERABILITY_NAMES

    return VULNERABILITY_NAMES


def test_the_payload_names_every_class_the_other_hook_fires_on():
    """The payload tells the agent where it is unassisted by naming what the other
    hook covers. A term added to security_terms.py without updating that sentence
    makes the payload wrong about the mechanism, silently.

    Only the named-class list is compared. security_terms.py also fires on a CVE id
    via a separate `_CVE` pattern, which is deliberately outside VULNERABILITY_NAMES
    and outside this check: the payload names classes an agent can recognise its own
    work in, and no finite list of CVE ids could be enumerated there.
    """
    payload = _payload().lower()
    missing = [n for n in _flagged_vulnerability_names() if n.lower() not in payload]
    assert not missing, (
        f"flag_security_topic fires on {missing} and the SessionStart payload does "
        "not list them, so it understates what is already covered"
    )


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
