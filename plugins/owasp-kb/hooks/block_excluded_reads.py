#!/usr/bin/env python3
"""Deny a tool call that would put an excluded prior assessment into context.

Why this exists: a finder grepped the excluded report and quoted a sentence from
the hit, having read "do not open them" as permitting a grep. The orchestrator
caught it and re-sourced the verdict, but nothing mechanical did -- and an agent
that reads an excluded file without naming it is indistinguishable from one that
never opened it.

SCOPE. The exclusion list lives at

    ${CLAUDE_CONFIG_DIR:-~/.claude}/owasp-kb/sessions/<session-id>/excluded

keyed on the session that wrote it. A session that never ran an assessment has no
such file, so every call is allowed and this cannot interfere with unrelated
work. That is structural rather than a policy being trusted, which is the only
reason a hook shipped in a plugin is acceptable at all. Nothing is written into
the target repository.

FAILS OPEN, deliberately. An unreadable payload, an unknown session, or any
exception allows the call. A hook that failed closed would break unrelated
sessions on a bug of its own -- worse than the leak it prevents. ``owasp_roster``
rejecting findings that cite an excluded path remains the real gate; this sits in
front of it.

It can block a call but cannot filter output, so a broad search is refused with
instructions to re-issue it excluding the path, rather than silently returning
redacted hits.

Python rather than node: node is not present in this project's container, and a
hook its own CI cannot exercise is an unexercised path by construction.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SEARCH_TOOLS = {"Read", "Grep", "Glob"}


def _list_file(session_id: str) -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return Path(base) / "owasp-kb" / "sessions" / session_id / "excluded"


def _exclusions(session_id: str) -> list[str]:
    try:
        lines = _list_file(session_id).read_text().splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _reaches(tool_name: str, tool_input: dict, excluded: str) -> bool:
    """Would this call put ``excluded`` in front of the agent?

    Two shapes. A path argument naming the file is unambiguous. A search rooted at
    a directory containing it is the case actually observed, and is allowed only
    when the call excludes the path itself -- the agent has to say so, rather than
    discard hits after seeing them.
    """
    target = str(tool_input.get("file_path") or tool_input.get("path") or "")
    # Grep's `pattern` is the search regex, not a file filter; only `glob` narrows
    # which files are read. Conflating them let a broad grep through, because a
    # pattern with no wildcard looked like an already-narrow file glob.
    glob = str(tool_input.get("glob") or "")
    stated = json.dumps(tool_input)

    if target and (target.endswith(excluded) or excluded.endswith(target)):
        return True
    if tool_name == "Read":
        return False

    root = target.lstrip("./")
    if root and not excluded.startswith(root):
        return False

    if re.search(rf"!.*{re.escape(excluded)}", stated):
        return False
    if glob and "*" not in glob and excluded not in glob:
        return False
    return True


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

    tool_name = payload.get("tool_name") or ""
    if tool_name not in SEARCH_TOOLS:
        return None

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return None

    for excluded in _exclusions(str(session_id)):
        if _reaches(tool_name, tool_input, excluded):
            return (
                f"Blocked: this call would put {excluded} into your context. It is a "
                "prior assessment of this same target, excluded for this run -- another "
                "assessment's conclusion is not evidence, and reading one makes you "
                "likely to confirm it rather than test it.\n\n"
                f"Re-issue the search excluding that path explicitly, for example "
                f"--glob '!{excluded}'. Do not filter the results afterwards: by then "
                "the text has reached you, which is the thing being prevented.\n\n"
                "If a verdict here would depend on excluded material, return "
                "INSUFFICIENT EVIDENCE and say so without naming the file."
            )
    return None


def main() -> int:
    try:
        reason = _decision(sys.stdin.read())
    except Exception:  # noqa: BLE001 -- see FAILS OPEN above
        reason = None
    if reason:
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            },
            sys.stdout,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
