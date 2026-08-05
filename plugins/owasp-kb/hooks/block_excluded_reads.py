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
from pathlib import Path, PurePosixPath

SEARCH_TOOLS = {"Read", "Grep", "Glob"}

# Which field holds the file filter, per tool. `Grep` narrows with `glob` and searches
# with `pattern`; `Glob` selects files with `pattern` and has no `glob` at all. Knowing
# only the first of those two fields is the whole of issue #33 -- a pathless `Glob` matched
# nothing the function looked at and fell through to the deny, 76 times in one run.
# `Read` is absent deliberately: it names a file, it does not filter.
FILTER_FIELD = {"Grep": "glob", "Glob": "pattern"}


def _list_file(session_id: str) -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return Path(base) / "owasp-kb" / "sessions" / session_id / "excluded"


def _exclusions(session_id: str) -> list[str]:
    try:
        lines = _list_file(session_id).read_text().splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _under(root: str, excluded: str) -> bool:
    """Does a search rooted at ``root`` recurse into ``excluded``?

    Both sides arrive in whichever form the writer used: an agent roots a search
    at ``docs`` or at ``/home/you/src/target/docs``, and the exclusion list holds
    an absolute path, a repository-relative one, or both. A plain
    ``excluded.startswith(root)`` only lines up when the two happen to match --
    and stripping the leading slash off the root to normalise it guaranteed they
    never would, so every absolute-rooted search was allowed through.

    Comparing on path segments makes the check independent of form: the root
    contains the file if either one's segment chain appears in the other. That
    covers all four combinations without the writer having to know which form the
    agent will use, which is what lets the exclusion list hold one path per report
    rather than two.

    It is deliberately generous -- a root matching only on its tail counts as
    containing the file. Over-refusing costs an agent one call that states the
    exclusion; under-refusing puts another assessment's conclusions in front of it.
    """
    r = root.removeprefix("./").strip("/")
    e = f"/{excluded.strip('/')}"
    if not r or r == ".":
        return True
    segments = r.split("/")
    return any(f"/{'/'.join(segments[i:])}/" in e for i in range(len(segments)))


def _selects(pattern: str, excluded: str) -> bool:
    """Can this file-selection pattern expand to ``excluded``?

    The search root is not knowable here. ``Glob`` roots at ``path`` when given and at the
    agent's cwd otherwise, and the exclusion list is written during scoping relative to the
    target repository root -- which a dispatched subagent's cwd need not be. So the pattern
    is tried against every suffix of the excluded path's segment chain: if the root is
    unknown, the file's path *relative to that root* is one of those suffixes. Same
    generosity ``_under`` documents, for the same reason.

    ``full_match`` supplies real glob semantics from the stdlib rather than a hand-rolled
    regex -- ``**`` crosses ``/`` and ``*`` does not, which is what makes ``docs/*.md``
    allowed against ``docs/security/rep.md`` while ``docs/**/*.md`` is denied.

    Rejected: expanding the pattern against the filesystem and testing set membership. It
    answers the same question by doing O(repo) work to decide something about one known
    path, ``Path.glob`` does not honour ``.gitignore`` so ``**/*`` walks ``.git`` and
    ``node_modules``, and this hook has a 5s timeout and fails open -- a slow walk turns
    into the leak it exists to prevent.

    Deliberate limit: an absolute pattern cannot match a list entry recorded only in
    relative form, because the absolute root is not knowable from the payload either. That
    under-refuses. ``_under`` still catches the rooted form of the same call, and
    ``owasp_roster`` rejecting findings that cite an excluded path remains the real gate.
    """
    segments = excluded.strip("/").split("/")
    root = "/" if pattern.startswith("/") else ""
    candidates = [
        PurePosixPath(root + "/".join(segments[i:])) for i in range(len(segments))
    ]
    return any(candidate.full_match(pattern) for candidate in candidates)


def _reaches(tool_name: str, tool_input: dict, excluded: str) -> bool:
    """Would this call put ``excluded`` in front of the agent?

    Three shapes. A path argument naming the file is unambiguous. A search rooted at a
    directory containing it is the case actually observed, and is allowed only when the
    call excludes the path itself -- the agent has to say so, rather than discard hits
    after seeing them. A search that *selects files by pattern* is allowed when the pattern
    cannot expand to the path, which is the ordinary way a narrow search proceeds.

    Ordering carries weight: ``_under`` releases an unrelated tree before the pattern is
    consulted, so ``path`` keeps bounding the search and a ``**/*`` aimed into the excluded
    directory is still refused.
    """
    target = str(tool_input.get("file_path") or tool_input.get("path") or "")
    stated = json.dumps(tool_input)

    if target and (target.endswith(excluded) or excluded.endswith(target)):
        return True
    if tool_name == "Read":
        return False

    if target and not _under(target, excluded):
        return False

    if re.search(rf"!.*{re.escape(excluded)}", stated):
        return False

    selector = str(tool_input.get(FILTER_FIELD.get(tool_name, ""), "") or "")
    if selector and not _selects(selector, excluded):
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
