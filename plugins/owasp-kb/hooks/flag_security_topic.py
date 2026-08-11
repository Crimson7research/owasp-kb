#!/usr/bin/env python3
"""Route a named vulnerability class to the knowledge base, once per session.

WHY THIS EXISTS. A session triaging an SSRF issue produced a repair plan without
consulting the corpus once. The skill was installed and listed, and the agent's own
account of why it skipped it was that the corpus "would add process overhead
without new insight here".

That judgement was made before looking, and it was wrong. The plan proposed an
allowlist -- correct in shape, since ASVS V1.3.6 asks for exactly that -- covering
domains, paths and ports, and never mentioned protocols, which is the first
dimension the requirement enumerates. It also proposed resolve-then-connect
validation, which the SSRF cheat sheet documents as bypassable via DNS pinning.

So the failure was not a missed cue. The skill was seen, priced, and declined. A
reminder that merely names the skill is disposed of by the same reasoning, which is
why the injected text argues about cost rather than value: checking is one call
now, and not checking risks a fix that ships, is believed done, and is reopened
later.

ONCE PER SESSION. Whether the skill was already invoked is not observable from
here -- a UserPromptSubmit hook receives the prompt, not the conversation. One
nudge per session is the achievable approximation and covers the intent: after it,
the agent has either acted or decided not to, and repeating the line changes
neither.

REACH IS WIDER THAN A HUMAN PROMPT. Observed: this hook fired on the text of a
task-notification carrying a subagent's report of work it had just done, not on
anything a person typed. The vocabulary is therefore matched against agent-generated
text too, which is a reason the payload argues rather than merely naming the skill --
the reader may be mid-implementation rather than mid-decision. It also means the one
nudge a session gets can be spent late: in that session it arrived after the code was
written, which is worth weighing against the once-per-session reasoning above.

FAILS OPEN, deliberately. Any exception exits 0 and emits nothing. Per ADR 0012 a
hook failing closed breaks unrelated sessions on a bug of its own, and this one
guards a reminder -- an open failure degrades to exactly the behaviour before it
existed, which is recognisable and survivable.

Python rather than node, for the reason block_excluded_reads.py gives: node is not
present in this project's container, and a hook its own CI cannot exercise is an
unexercised path by construction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

NUDGE = """This prompt names a vulnerability class ({term}).

Your recollection of it may be incomplete or out of date, and you cannot tell \
which from the inside. Requirements in this area typically enumerate several \
dimensions a fix has to cover; missing one produces a fix that looks correct and \
is not.

The costs are not symmetric. Checking is one owasp_search call, now. Not checking \
risks a fix that ships, is believed done, and has to be reopened and redone later \
-- after the code is in.

So call it before deciding the approach, not to confirm one you already chose. \
Then cite the ASVS ids and Cheat Sheet anchors you relied on, or state plainly \
that you answered from memory.

Absence of security framing in the request is not evidence of absence of security \
relevance. A refactor that moves a credential or a request destination changes the \
surface even when the diff looks mechanical.

Measured on a session that skipped this check: the check itself cost six minutes, \
against the three hours and twenty minutes of planning it should have informed. That \
checking is cheap was already stated above, and was declined anyway. The point here is \
narrower -- it landed before the code by luck, two tasks ahead of the implementation, \
and nothing arranges that.

Check whether this codebase already has the control before you design one. That \
session was about to hand-roll a validator its own repository already had, and to \
"fix" redirects by disabling them where an existing guard re-validated every hop. The \
corpus cannot tell you either -- grep for the control names the guidance uses."""


def _context() -> str | None:
    """The text to inject, or None to stay silent.

    Every import and file touch happens inside this function so that main()'s
    handler catches anything -- including an import failure, which at module scope
    would kill the process before the fail-open path could run.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
    from owasp_kb_cli.security_terms import matched_term
    from owasp_kb_cli.state import session_dir

    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        return None

    term = matched_term(payload.get("prompt") or "")
    if not term:
        return None

    session = payload.get("session_id")
    if not session:
        return None

    # session_dir validates the id, so a payload carrying a separator or `..`
    # raises here and the hook falls open rather than writing outside the tree.
    marker = session_dir(str(session)) / "security-flagged"
    if marker.exists():
        return None
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(f"{term}\n")
    return NUDGE.format(term=term)


def main() -> int:
    try:
        context = _context()
    except Exception:  # noqa: BLE001 -- see FAILS OPEN above
        return 0
    if context:
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": context,
                }
            },
            sys.stdout,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
