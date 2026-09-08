#!/usr/bin/env python3
"""State where the host CLI lives, at every session start.

WHY THIS EXISTS. The tools left bin/ so that nothing this plugin ships reaches
PATH: Claude Code appends `<plugin_root>/bin` unconditionally, and whatever lands
there is invisible on the admin approval surface an org admin approves the plugin
from -- which is why organization sync rejects a plugin shipping bin/ at all
(ADR 0018). Off PATH, a bare `owasp-kb` is command-not-found, so the absolute
path has to reach the agent some other way.

There is exactly one other way. CLAUDE_PLUGIN_ROOT is set for a hook process and
not for a Bash tool call, verified against the live environment, so an agent
cannot compute this path from inside the call that needs it. The process that can
resolve it is this one, and so this one says it -- unconditionally, in plain
absolute form, with nothing left to compute.

UNCONDITIONAL, for a reason of its own rather than by inheritance from
nudge_secure_coding.py. `doctor` and `sessions` serve a machine with no
assessment in flight -- checking an install, listing what is on disk -- so gating
the note on session state would leave them unreachable in exactly the case where
`doctor` is what someone needs.

SEPARATE FROM THE NUDGE, deliberately. The two payloads fail in opposite
directions: the nudge failing open to silence is correct and ADR 0017 argues it,
because a session must not break over a reminder. This note falling silent is a
command-not-found later. Sharing one process would let an exception in path
resolution suppress the nudge, and a malformed nudge suppress the path. ADR 0017
also bounds the nudge with "its only bound is that it is short", and appending a
tools inventory to a payload whose entire defence is brevity spends that bound.

FAILS OPEN anyway, for the reason above: an exception exits 0 and emits nothing.
The degraded state is a longer road to the path, not a broken session.

Python rather than node, for the reason block_excluded_reads.py gives: node is
not present in this project's container, and a hook its own CI cannot exercise is
an unexercised path by construction.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The commands the entry point registers. Duplicated rather than imported, and
# not because a hook cannot import from scripts/ -- flag_security_topic.py does
# exactly that to reach owasp_kb_cli.security_terms. The entry point is the
# problem: `owasp-kb` is hyphenated, so it is not an importable module name, and
# its subparsers are built inside main() rather than at module level, so reading
# them means constructing the parser. A three-word tuple that a test compares
# against the real parsers is cheaper and fails just as loudly.
COMMANDS = ("report merge", "doctor", "sessions")


def scripts_directory() -> Path:
    """Where the plugin's tools live, absolute.

    CLAUDE_PLUGIN_ROOT when the harness sets it -- the installed copy is a cache
    directory, not a checkout. The __file__ fallback keeps the function
    answerable when a test invokes this hook directly from the repository.
    """
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    base = Path(root) if root else Path(__file__).resolve().parent.parent
    return (base / "scripts").resolve()


def note() -> str:
    directory = scripts_directory()
    return (
        f"<owasp-kb-tools>\n"
        f"This plugin's command-line tools are in {directory}. They are not on "
        f"PATH: invoke one by absolute path, as `python3 {directory}/owasp-kb "
        f"<command>`. The commands are {', '.join(COMMANDS)}.\n"
        f"</owasp-kb-tools>"
    )


def _context() -> str:
    """The text to inject.

    stdin is read and discarded: emission is unconditional, so nothing in the
    payload is consulted. It is read anyway rather than left in the pipe, and it
    is read inside this function so that main()'s handler covers it.
    """
    sys.stdin.read()
    return note()


def main() -> int:
    try:
        # Serialised in full before anything is written, for the reason
        # nudge_secure_coding.py gives: json.dump streams chunks into the stream,
        # so a mid-write failure leaves a truncated object on stdout.
        payload = json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": _context(),
                }
            }
        )
        # Written through a duplicate of fd 1, never through sys.stdout -- see the
        # measurement in nudge_secure_coding.py: the sys.stdout form exits 120 on
        # CI and on Python 3.14, this form exits 0.
        with os.fdopen(os.dup(1), "wb") as out:
            out.write(payload.encode())
    except Exception:  # noqa: BLE001 -- see FAILS OPEN above
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
