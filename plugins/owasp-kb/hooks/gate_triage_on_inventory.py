#!/usr/bin/env python3
"""Refuse a triage dispatch while the scope inventory is still short a concern.

Why this exists: ``owasp_roster`` gates every stage that produces a verdict, and
#58 moved the verification gate into it precisely because an instruction is not
enforceable. The scope inventory produces *facts*, so no verdict carries it and
no roster field counts it -- on one run four of five inventory agents returned,
triage ran over the hole, and the ~150 agents dispatched afterwards all worked
from the same partial picture. A triage over a partial inventory looks exactly
like a triage over a complete one, which is why nothing noticed.

SCOPE. Two files, keyed on the session that wrote them:

    ${CLAUDE_CONFIG_DIR:-~/.claude}/owasp-kb/sessions/<session-id>/concerns
    ${CLAUDE_CONFIG_DIR:-~/.claude}/owasp-kb/sessions/<session-id>/inventory.md

The concerns list is written when the inventory agents go out, and it is what
arms this. A session that never ran an assessment has no such file, so every call
is allowed and unrelated work cannot be affected -- structural rather than a
policy being trusted, which is the only reason a hook shipped in a plugin is
acceptable at all. Nothing is written into the target repository.

Only ``owasp-chapter-orchestrator`` and ``owasp-exemption-refuter`` are gated.
``owasp-scope-inventory`` is what fills the file, so gating it would deadlock the
stage; a finder or verifier is dispatched after triage, when the gate has already
been satisfied.

FAILS OPEN, deliberately, and the asymmetry runs the other way from
``block_excluded_reads.py``: there an over-refusal costs one call that states the
exclusion, here it would stop the assessment. So a malformed payload, an unknown
session, a missing or empty concerns list, or any exception allows the call.

Python rather than node: node is not present in this project's container, and a
hook its own CI cannot exercise is an unexercised path by construction.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# `Task` in the harness this plugin targets, `Agent` in others. Matching one
# would leave the gate inert wherever the other is used.
DISPATCH_TOOLS = {"Task", "Agent"}

# The two roles that decide something from the inventory: an orchestrator runs a
# chapter triage said applies, a refuter tries to disprove an exemption triage
# inferred. Matched as substrings because a plugin agent arrives namespaced --
# `owasp-kb:owasp-chapter-orchestrator` -- in some harnesses and bare in others.
GATED_ROLES = ("owasp-chapter-orchestrator", "owasp-exemption-refuter")


def _session_dir(session_id: str) -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return Path(base) / "owasp-kb" / "sessions" / session_id


def _lines(path: Path) -> list[str]:
    try:
        raw = path.read_text().splitlines()
    except OSError:
        return []
    return [line.strip() for line in raw if line.strip() and not line.startswith("#")]


def _normalise(text: str) -> str:
    """Fold the differences between how a concern is written in two places.

    The concerns list holds one token per line, so a two-word concern is written
    `client-surface` there and reads as `## Client surface` as a heading. Folding
    case and the word separators is what lets both be the same concern without
    the agent having to know which form this compares.
    """
    return " ".join(text.lower().replace("-", " ").replace("_", " ").split())


def _level(line: str) -> int:
    stripped = line.lstrip()
    return len(stripped) - len(stripped.lstrip("#"))


def _surveyed(inventory: str) -> list[str]:
    """Heading text for each section of ``inventory.md`` that has a body.

    The body requirement is what stops the trivial pass: a file of bare headings
    satisfies an existence check while surveying nothing, and an unsurveyed
    concern is the entire failure being prevented. A concern that found nothing
    still passes by saying so -- "no client-side surface exists" is a fact and a
    legitimate section body.

    **A body counts for every heading above it.** The first real run wrote each
    concern as a `##` heading with all of its content in `###` subsections, so a
    per-heading rule called the concern itself bodiless: four of six passed only
    because a subheading happened to contain the concern word
    (`### logging middleware`). Worded differently, a complete 40,000-character
    inventory would have been refused forever -- the gate stopping the assessment
    rather than the hole it guards. Inheriting upward keeps both halves: a parent
    whose content lives in subsections is surveyed, and a heading with nothing
    under it anywhere still is not.

    A fenced block is content, and its `#` comment lines are not headings. A
    `# endpoints` comment inside a code block would otherwise satisfy a concern.
    """
    surveyed: list[str] = []
    open_headings: list[tuple[int, str, bool]] = []
    in_fence = False

    def close_to(level: int) -> None:
        while open_headings and open_headings[-1][0] >= level:
            _, text, has_body = open_headings.pop()
            if has_body:
                surveyed.append(text)

    def mark_body() -> None:
        open_headings[:] = [(lvl, text, True) for lvl, text, _ in open_headings]

    for line in inventory.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            mark_body()
        elif in_fence:
            if line.strip():
                mark_body()
        elif line.lstrip().startswith("#"):
            close_to(_level(line))
            open_headings.append((_level(line), _normalise(line), False))
        elif line.strip():
            mark_body()

    close_to(0)
    return surveyed


def _missing(concerns: list[str], inventory: str) -> list[str]:
    """Which concerns no section covers.

    Matched on containment of the normalised forms rather than equality: the
    agent writes both files, so it can name a section after the concern it
    listed, but a gate insisting on the exact string would deny a run over a
    plural, a capital or a hyphen -- and the agent cannot see the comparison
    being made.
    """
    surveyed = _surveyed(inventory)
    return [c for c in concerns if not any(_normalise(c) in heading for heading in surveyed)]


def _reason(role: str, path: Path, concerns: list[str], missing: list[str]) -> str:
    covered = [c for c in concerns if c not in missing]
    state = ", ".join(covered) if covered else "nothing yet"
    return (
        f"Blocked: {role} was dispatched before the scope inventory was complete. Triage "
        "decides applicability from the inventory, so a chapter judged over a hole in it is "
        "judged on a partial picture -- and that is indistinguishable in the output from one "
        "judged on a complete one.\n\n"
        f"{path} covers {state} — missing: {', '.join(missing)}.\n\n"
        "Merge each owasp-scope-inventory agent's return into that file under a heading naming "
        "its concern, with its file and line references under the heading, then re-dispatch "
        "this agent. If an inventory agent failed rather than returned, re-dispatch that agent "
        "first: four of five returning is the case this exists to catch, because nothing "
        "downstream counts the inventory the way owasp_roster counts a verdict.\n\n"
        'A concern that found nothing still gets a section saying so — "no client-side surface '
        'exists in this target" is a survey result. A heading with nothing under it is not, and '
        "does not satisfy this check."
    )


def _decision(raw: str) -> str | None:
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    session_id = payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID")
    if not session_id:
        return None

    if (payload.get("tool_name") or "") not in DISPATCH_TOOLS:
        return None

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return None

    subagent = str(tool_input.get("subagent_type") or "")
    role = next((gated for gated in GATED_ROLES if gated in subagent), None)
    if role is None:
        return None

    session = _session_dir(str(session_id))
    concerns = _lines(session / "concerns")
    if not concerns:
        return None

    inventory_path = session / "inventory.md"
    try:
        inventory = inventory_path.read_text()
    except OSError:
        inventory = ""

    missing = _missing(concerns, inventory)
    if not missing:
        return None
    return _reason(role, inventory_path, concerns, missing)


def main() -> int:
    try:
        reason = _decision(sys.stdin.read())
    except Exception:  # noqa: BLE001 -- see FAILS OPEN above
        reason = None
    if reason:
        try:
            # Serialised in full before anything is written: json.dump streams
            # chunks into the stream, so a mid-write failure leaves a truncated
            # decision on stdout, which is worse than the nothing this hook
            # promises. The flush is load-bearing too -- without it CPython flushes
            # at interpreter shutdown, outside any handler, and an unflushable
            # buffer there sets exit status 120 whatever main() returned.
            payload = json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
            )
            # Written through a duplicate of fd 1, never through sys.stdout. A failed
            # write leaves the payload sitting in sys.stdout's buffer, and CPython
            # flushes that again at interpreter shutdown -- outside any handler, which
            # sets exit status 120 whatever main() returned. Nothing is ever buffered on
            # sys.stdout, so that retry has nothing left to fail on. Measured: the
            # sys.stdout form exits 120 on CI and on Python 3.14; this form exits 0.
            with os.fdopen(os.dup(1), "wb") as out:
                out.write(payload.encode())
        except Exception:  # noqa: BLE001 -- see FAILS OPEN above
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
