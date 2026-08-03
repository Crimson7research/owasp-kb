"""The PreToolUse hook that stops triage running over a partial scope inventory.

`owasp_roster` gates every stage that produces a verdict. The scope inventory
produces facts, so nothing counts it, and a run where four of five inventory
agents returned dispatched its seventeen chapters over the gap without anything
noticing. Triage over a partial inventory looks exactly like triage over a
complete one.

These pin both halves: that a gated role is refused while a concern has no
section, and -- more important -- that a session which never ran an assessment
cannot be affected.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path("plugins/owasp-kb/hooks/gate_triage_on_inventory.py")

CONCERNS = ["endpoints", "middleware", "identity", "storage", "client surface"]

COMPLETE = """# Scope inventory — factual, no verdicts

## Endpoints
`src/net/http.c:40` registers 12 routes.

## Middleware
No middleware chain exists; handlers are called directly.

## Identity
`src/auth/user.c:88` holds the credential store.

## Storage
NVS partition, `src/store/nvs.c:12`.

## Client surface
`web/app.js:1` serves a single-page console.
"""

# The observed failure: one agent never returned, so its section was never written.
PARTIAL = COMPLETE.split("## Client surface")[0]


def _run(payload: dict | str, config_dir: Path) -> dict | None:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=raw,
        capture_output=True,
        text=True,
        env={**os.environ, "CLAUDE_CONFIG_DIR": str(config_dir)},
    )
    assert result.returncode == 0, f"hook must never fail the call: {result.stderr}"
    return json.loads(result.stdout) if result.stdout.strip() else None


def _denied(out: dict | None) -> bool:
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def _reason(out: dict | None) -> str:
    return out["hookSpecificOutput"]["permissionDecisionReason"]


def _state(tmp_path, *, concerns=CONCERNS, inventory: str | None = PARTIAL) -> Path:
    session = tmp_path / "owasp-kb" / "sessions" / "sess-1"
    session.mkdir(parents=True)
    if concerns is not None:
        (session / "concerns").write_text("".join(f"{c}\n" for c in concerns))
    if inventory is not None:
        (session / "inventory.md").write_text(inventory)
    return tmp_path


@pytest.fixture
def partial(tmp_path):
    """Four of five concerns surveyed -- the state that shipped a full triage."""
    return _state(tmp_path)


def _dispatch(subagent_type, tool="Task", session="sess-1"):
    return {
        "session_id": session,
        "tool_name": tool,
        "tool_input": {"subagent_type": subagent_type, "prompt": "Assess V6 at L2"},
    }


GATED = ["owasp-chapter-orchestrator", "owasp-exemption-refuter"]


@pytest.mark.parametrize("role", GATED)
def test_a_gated_role_is_denied_while_a_concern_has_no_section(partial, role):
    """Both roles decide something from the inventory: the orchestrator runs a
    chapter triage said applies, the refuter tries to disprove an exemption
    triage inferred. Neither judgement is sound over a hole."""
    assert _denied(_run(_dispatch(role), partial))


@pytest.mark.parametrize("role", GATED)
def test_a_complete_inventory_lets_the_dispatch_through(tmp_path, role):
    assert not _denied(_run(_dispatch(role), _state(tmp_path, inventory=COMPLETE)))


def test_a_missing_inventory_is_denied(tmp_path):
    """The concerns file is written when the inventory agents go out, so between
    that and their returns there is no inventory.md at all."""
    out = _run(_dispatch("owasp-chapter-orchestrator"), _state(tmp_path, inventory=None))
    assert _denied(out)
    assert "inventory.md" in _reason(out)


def test_a_heading_with_no_body_does_not_count_as_coverage(tmp_path):
    """The trivial pass. A file of bare headings satisfies an existence check
    while surveying nothing, and an unsurveyed concern is the whole failure."""
    headings_only = COMPLETE.split("## Client surface")[0] + "## Client surface\n"
    assert _denied(
        _run(_dispatch("owasp-chapter-orchestrator"), _state(tmp_path, inventory=headings_only))
    )


def test_an_empty_section_followed_by_another_does_not_count_either(tmp_path):
    """The same check, for a section that is not the last one in the file. A
    body requirement applied only to the trailing section passes every run whose
    hole happens to be in the middle -- and which concern the missing agent was
    surveying is not something the file's order can be relied on to reflect.
    """
    reordered = COMPLETE.replace(
        "## Client surface\n`web/app.js:1` serves a single-page console.\n",
        "",
    ).replace("## Storage", "## Client surface\n## Storage")
    assert _denied(
        _run(_dispatch("owasp-chapter-orchestrator"), _state(tmp_path, inventory=reordered))
    )


# The shape a real 40KB inventory actually took (session 2db23b19): the concern is a
# `##` heading and everything under it lives in `###` subsections, so the concern
# heading has no line of its own before the next heading.
NESTED = """# Scope inventory — factual, no verdicts

## endpoints

### UART / RS485
`src/uart.cpp:40` reads frames at 9600 8N1.

### Modbus RTU frame ingress
`src/modbus.cpp:88` parses the function code.

## client surface

### Web console
None. This firmware exposes no HTTP surface.
"""


def test_a_concern_whose_content_lives_in_subsections_is_covered(tmp_path):
    """The shape the first real run produced. A body requirement applied per
    heading counts a `##` concern as bodiless whenever its content sits in `###`
    subsections -- and in that run four of six concerns passed only because some
    subheading happened to contain the concern word (`### logging middleware`).
    Worded differently, a complete 40KB inventory would have been refused forever
    and the gate, not the leak, would have stopped the assessment."""
    state = _state(tmp_path, concerns=["endpoints", "client-surface"], inventory=NESTED)
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator"), state))


def test_a_concern_with_empty_subsections_is_still_not_covered(tmp_path):
    """The other half: inheriting a body from a subsection must not become a way
    for a heading with nothing under it anywhere to pass. Otherwise the trivial
    pass comes back one level down."""
    hollow = (
        "# Scope inventory\n\n## endpoints\n### UART\n### Modbus\n\n"
        "## storage\nNVS, `nvs.cpp:12`.\n"
    )
    state = _state(tmp_path, concerns=["endpoints", "storage"], inventory=hollow)
    out = _run(_dispatch("owasp-chapter-orchestrator"), state)
    assert _denied(out)
    assert "endpoints" in _reason(out).split("missing:", 1)[1]


def test_a_hash_comment_inside_a_code_block_is_not_a_heading(tmp_path):
    """An inventory quotes config and source, and a `#` comment at column zero
    inside a fence would otherwise satisfy a concern nobody surveyed. The fence
    itself is content, so the section holding it still has a body."""
    fenced = "# Scope inventory\n\n## storage\n```ini\n# endpoints\nCONFIG_NVS=y\n```\n"
    state = _state(tmp_path, concerns=["endpoints", "storage"], inventory=fenced)
    out = _run(_dispatch("owasp-chapter-orchestrator"), state)
    assert _denied(out), "a code comment must not stand in for a surveyed concern"
    missing = _reason(out).split("missing:", 1)[1]
    assert "endpoints" in missing
    assert "storage" not in missing, "the fence is content, so its section has a body"


def test_a_concern_that_found_nothing_is_covered_by_saying_so(tmp_path):
    """ "No client-side surface exists" is a fact, and the section stating it is a
    survey result. Requiring more would make the hook the thing that stops the
    assessment rather than the leak it guards."""
    nothing_found = (
        COMPLETE.split("## Client surface")[0]
        + "## Client surface\nNone. This firmware exposes no HTTP or UI surface.\n"
    )
    assert not _denied(
        _run(_dispatch("owasp-chapter-orchestrator"), _state(tmp_path, inventory=nothing_found))
    )


@pytest.mark.parametrize(
    "heading",
    ["## Cryptography", "## CRYPTO PRIMITIVES", "### Crypto and key handling"],
    ids=["longer-word", "shouted", "deeper-level"],
)
def test_a_heading_covers_a_concern_regardless_of_case_or_surrounding_words(tmp_path, heading):
    """The agent writes both files, so it can name a section after the concern it
    listed -- but a gate that insisted on the exact string would deny a run over
    a plural or a capital, and the agent cannot see the comparison being made."""
    inventory = f"# Scope inventory\n\n{heading}\nmbedTLS 3.4, `src/crypto/tls.c:22`.\n"
    state = _state(tmp_path, concerns=["crypto"], inventory=inventory)
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator"), state))


@pytest.mark.parametrize(
    ("concern", "heading"),
    [
        ("client-surface", "## Client surface"),
        ("client_surface", "## Client surface"),
        ("client surface", "## Client-surface"),
    ],
    ids=["hyphen-vs-space", "underscore-vs-space", "space-vs-hyphen"],
)
def test_a_word_separator_does_not_make_it_a_different_concern(tmp_path, concern, heading):
    """A concerns file holds one token per line, so a two-word concern is written
    `client-surface` there and reads as `## Client surface` as a heading. Both
    name the same thing, and a gate that disagreed would refuse a complete
    inventory over a separator the agent had no way to know was compared."""
    inventory = f"# Scope inventory\n\n{heading}\n`web/app.js:1` serves a console.\n"
    state = _state(tmp_path, concerns=[concern], inventory=inventory)
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator"), state))


@pytest.mark.parametrize("tool", ["Task", "Agent"], ids=["task", "agent"])
def test_both_dispatch_tool_names_are_gated(partial, tool):
    """The dispatch tool is `Task` in the harness the plugin targets and `Agent`
    in others. Matching one leaves the gate inert wherever the other is used."""
    assert _denied(_run(_dispatch("owasp-chapter-orchestrator", tool=tool), partial))


def test_a_namespaced_subagent_type_is_gated(partial):
    """A plugin agent arrives as `owasp-kb:owasp-chapter-orchestrator` in some
    harnesses and bare in others, and an exact-match gate would pass the run it
    exists to stop."""
    assert _denied(_run(_dispatch("owasp-kb:owasp-chapter-orchestrator"), partial))


@pytest.mark.parametrize(
    "role",
    ["owasp-scope-inventory", "owasp-requirement-finder", "owasp-finding-verifier", "Explore"],
    ids=["inventory", "finder", "verifier", "unrelated"],
)
def test_only_the_two_triage_roles_are_gated(partial, role):
    """The inventory agent is what fills the file, so gating it would deadlock the
    stage. A finder and a verifier are dispatched after triage, when the gate has
    already been satisfied -- refusing them would block a chapter's own fan-out
    on a check that already passed."""
    assert not _denied(_run(_dispatch(role), partial))


# -- isolation: the property that lets this ship at all ----------------------


def test_no_concerns_file_allows_everything(tmp_path):
    """The concerns list is what arms the gate. No file means no assessment is
    running in this session, so nothing is gated."""
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator"), tmp_path))


def test_an_empty_concerns_file_allows_everything(tmp_path):
    """A file written but not filled in states no concern, so it can name none as
    missing. Denying on it would block a run over a bookkeeping slip."""
    state = _state(tmp_path, concerns=[], inventory=None)
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator"), state))


def test_another_session_is_untouched(partial):
    """Keyed on the session that wrote it, like the exclusion list."""
    assert not _denied(_run(_dispatch("owasp-chapter-orchestrator", session="sess-other"), partial))


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "",
        '{"tool_name":"Task"}',
        '{"session_id":"sess-1"}',
        '{"session_id":"sess-1","tool_name":"Task","tool_input":"nope"}',
    ],
    ids=["malformed", "empty", "no-session", "no-tool", "bad-input"],
)
def test_an_unusable_payload_allows_the_call(payload, partial):
    """Fails open on purpose, and the asymmetry runs the other way from the
    exclusion hook: an over-refusal here stops the assessment rather than costing
    one call that states the exclusion."""
    assert not _denied(_run(payload, partial))


def test_the_denial_names_the_missing_concern_and_what_to_write(partial):
    """A refusal an agent cannot act on gets worked around. It has to say which
    concern is short, that a nothing-found section still counts, and that an
    inventory agent which failed rather than returned needs re-dispatching --
    otherwise the agent writes an empty heading to get past the gate."""
    reason = _reason(_run(_dispatch("owasp-chapter-orchestrator"), partial))
    assert "client surface" in reason
    assert "inventory.md" in reason
    assert "owasp-scope-inventory" in reason
    assert "re-dispatch" in reason.lower()


def test_the_denial_does_not_list_a_covered_concern(partial):
    """Naming every concern would leave the agent to work out which one is short,
    and the one it is missing is the only actionable fact."""
    reason = _reason(_run(_dispatch("owasp-chapter-orchestrator"), partial))
    missing = reason.split("missing:", 1)[1]
    assert "endpoints" not in missing.lower()
