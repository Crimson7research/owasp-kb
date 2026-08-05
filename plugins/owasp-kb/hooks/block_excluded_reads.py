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
import posixpath
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

    Compared as segment lists rather than rebuilt-and-rescanned strings: joining a
    candidate suffix and searching for it as a substring is quadratic in ``root``'s
    segment count, and ``root`` is attacker-influenced the same way a pattern is -- a
    ``path`` fifty thousand directories deep took 6.5s against the string form, past
    this hook's 5s timeout, and a timeout fails open. The candidate range is bounded to
    suffixes no longer than ``excluded``'s own chain, since a longer one cannot match
    regardless of how deep ``root`` goes.
    """
    r = root.removeprefix("./").strip("/")
    e = f"/{excluded.strip('/')}"
    if not r or r == ".":
        return True
    segments = r.split("/")
    excluded_segments = e.strip("/").split("/")
    total = len(excluded_segments)
    width = len(segments)
    return any(
        j + (width - i) < total and excluded_segments[j : j + width - i] == segments[i:]
        for i in range(max(0, width - total), width)
        for j in range(total)
    )


def _split_at_first_wildcard(pattern: str) -> tuple[str, str]:
    """``/a/b/**/*.md`` -> ``("/a/b", "**/*.md")``. No wildcard at all -> ``(pattern, "")``."""
    segments = pattern.split("/")
    for i, segment in enumerate(segments):
        if any(char in segment for char in "*?["):
            return "/".join(segments[:i]), "/".join(segments[i:])
    return pattern, ""


def _selects_across_forms(pattern: str, segments: list[str]) -> bool:
    """An absolute pattern against a path recorded relative.

    Neither form carries the other's root, so no suffix of the excluded path can line up
    with the pattern as written -- which is why matching it directly allowed a whole-tree
    ``/abs/root/**`` sweep. Discard the pattern's literal leading directory, which is the
    part that names the root we cannot see, and match the remainder: it is the part that
    describes the search, and it is form-independent.

    A pattern with no wildcard has no remainder and is a filename, so it is compared as
    one.
    """
    literal, remainder = _split_at_first_wildcard(pattern)
    if not remainder:
        return literal.rstrip("/").endswith("/".join(segments))
    return any(
        PurePosixPath("/".join(segments[i:])).full_match(remainder) for i in range(len(segments))
    )


# Bounds on brace expansion. It is a product of the groups, and this hook has a 5s timeout
# and fails open -- so a pattern past the bound is refused rather than expanded.
BRACE_GROUPS = 4
BRACE_ALTERNATIVES = 16

# Ceilings on what one ``_selects`` call may cost. It tries every alternative against every
# suffix of the excluded path, so expanding a brace list multiplies a cost that used to be
# linear in that path's depth -- at the bound above, by 625. Past either ceiling the pattern
# is refused rather than matched, the same trade ``_expand_braces`` makes and for the same
# reason: the 5s timeout fails open, so the slow path is the leak.
#
# The depth ceiling is the separate one because building those suffixes is quadratic in the
# depth, not linear: a 4000-segment entry cost 0.9s and an 8000-segment one exhausted 2GB
# and raised, which ``main`` catches into an allow. That predates brace expansion -- it is
# the same shape ``_under`` documents -- but the product ceiling alone does not bound it,
# since a single alternative leaves the depth free. ``_covers`` needs neither, matching each
# alternative once against one path rather than per suffix.
MATCH_BUDGET = 50_000
MAX_DEPTH = 1_000


def _split_alternatives(body: str) -> list[str]:
    """Split ``a,b{c,d}`` on its top-level commas, leaving a nested group intact."""
    parts: list[str] = []
    depth = 0
    current = ""
    for char in body:
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        depth += (char == "{") - (char == "}")
        current += char
    parts.append(current)
    return parts


def _expand_braces(pattern: str) -> list[str] | None:
    """``*.{ts,tsx}`` -> ``["*.ts", "*.tsx"]``. ``None`` for a pattern past the bound.

    ``full_match`` has no brace support, so an unexpanded ``docs/**/*.{md,txt}`` matches
    nothing -- which in ``_selects`` is an allow, and a brace list is what an agent writes
    to search two extensions at once.

    An unbalanced ``{`` is returned untouched: it is a legal character in a filename, and
    guessing at it would be worse than matching it literally. Ripgrep rejects such a glob
    outright, so the search returns nothing either way.

    The caller decides what a ``None`` means, because the two callers fail in opposite
    directions -- see ``_selects`` and ``_covers``.
    """
    if pattern.count("{") > BRACE_GROUPS or pattern.count(",") > BRACE_ALTERNATIVES:
        return None
    start = pattern.find("{")
    if start == -1:
        return [pattern]
    depth = 0
    for i in range(start, len(pattern)):
        depth += (pattern[i] == "{") - (pattern[i] == "}")
        if depth == 0:
            head, body, tail = pattern[:start], pattern[start + 1 : i], pattern[i + 1 :]
            expanded: list[str] = []
            for alternative in _split_alternatives(body):
                nested = _expand_braces(f"{head}{alternative}{tail}")
                if nested is None:
                    return None
                expanded.extend(nested)
            return expanded
    return [pattern]


def _covers(pattern: str, excluded: str) -> bool:
    """Does ``!pattern`` certainly put ``excluded`` out of the search?

    Deliberately the mirror of ``_selects``. That one over-approximates -- it matches
    every suffix of the excluded path because the search root is unknowable, and an
    over-approximation there means a denial. Negation reverses which way an error falls,
    so reusing it and inverting turned each of those over-approximations into an allow:
    ``--glob '!security/*.md'`` was read as excluding the report when ripgrep anchors it
    to the search root and it excludes nothing at all -- verified against a real ripgrep,
    which still found the report under that negation.

    So this one under-approximates, and follows the gitignore semantics ripgrep actually
    implements: a glob containing ``/`` is anchored to the search root and must match the
    whole recorded path; a glob without one matches a basename at any depth. Anything it
    cannot prove is a refusal.

    Deliberately does *not* normalise, unlike ``_selects``. ``posixpath.normpath`` treats
    ``.``, ``..`` and an empty segment as navigation and resolves them away; ``PurePath``'s
    own pattern parsing silently does the same for ``.`` and an empty segment (though not
    for ``..``, which it keeps as a literal segment that then happens to fail to match
    anything real -- an implementation detail this refusal does not rely on). Ripgrep's
    globset matches a glob against the walked path verbatim, where all three are literal
    path components that match nothing there either. Normalising first read ``!./docs/**``
    as covering the report while a real ripgrep handed the report straight over. Refusing
    to prove coverage whenever such a segment appears is the safe direction here, the same
    way over-approximating is the safe direction in ``_selects``.

    A leading ``/`` anchors the pattern to the search root rather than naming an absolute
    filesystem path, so it is stripped -- at most once -- before matching: ``!/docs/**``
    does exclude a relative ``excluded`` and must be allowed, while ``!/elsewhere/docs/**``
    still does not and is refused. Whether the pattern is anchored has to be decided on the
    *un-stripped* pattern, though: for a single-component glob like ``/*.md`` the leading
    ``/`` is the only ``/`` in it, and stripping it before asking "does this have a ``/``"
    reclassified it as basename-at-any-depth -- exactly the reach a leading ``/`` exists to
    remove. ``!/*.md`` does not exclude the report and must stay refused.

    A trailing ``/`` means "this directory" in gitignore syntax, so it is rewritten as a
    recursive descent (``docs/`` becomes ``docs/**``) rather than left to trip the segment
    guard's empty-segment case: ``!docs/`` and ``!docs/security/`` do exclude the report and
    must be allowed, matching a real ripgrep, while ``!firmware/`` and a wildcard segment
    immediately before the slash still do not.

    A brace list is expanded, and covers the path when *any* alternative matches it -- that
    is what the glob means, since matching any alternative excludes the file. ``None`` from
    ``_expand_braces``, for a pattern past its bound, is a refusal: coverage is what has to
    be proven here, so failing to expand proves nothing. That is the mirror of ``_selects``,
    where a ``None`` is a match, and both land on a denial.

    Whether the pattern is anchored, and the leading and trailing ``/``, are decided on the
    unexpanded pattern, because ripgrep decides them once for the whole glob rather than per
    alternative: under ``!{a/b,*.md}`` a real ripgrep still returns a report three levels
    down, the separator in the *other* alternative having anchored ``*.md`` too.

    The segment guard, in contrast, must run per alternative and after expansion. A brace
    hides the offending segment from a guard that runs first -- ``{./docs,zz}`` splits into
    ``{.`` and ``docs,zz}``, neither of which is a bare ``.`` -- and expansion then hands
    ``./docs/**`` to a ``full_match`` that silently drops the ``.`` and reports a match,
    while a real ripgrep returns the report. An alternative carrying such a segment covers
    nothing, so it is skipped; the others still decide.
    """
    anchored = "/" in pattern
    pattern = pattern.removeprefix("/")
    if pattern.endswith("/"):
        pattern = pattern.removesuffix("/") + "/**"
    alternatives = _expand_braces(pattern)
    if alternatives is None:
        return False
    path = PurePosixPath(excluded)
    candidate = path if anchored else PurePosixPath(path.name)
    return any(
        # ripgrep matches a glob against the walked path verbatim: `.`, `..` and empty
        # segments are literal components there, so an alternative carrying one excludes
        # nothing. Normalising them away was an over-approximation, and in this branch an
        # over-approximation is an allow -- `!./docs/**` read as covering the report
        # while ripgrep handed the report over.
        all(segment not in ("", ".", "..") for segment in alternative.split("/"))
        and candidate.full_match(alternative)
        for alternative in alternatives
    )


def _selects(pattern: str, excluded: str) -> bool:
    """Can this file-selection pattern expand to ``excluded``?

    Every alternative is normalised with ``posixpath.normpath``. ``full_match`` does not
    collapse ``..`` or redundant slashes on its own, so ``docs/../docs/**/*.md`` would
    otherwise fail to line up with the equivalent ``docs/**/*.md`` and the file would walk
    out through the one segment nothing checked.

    Normalising happens *after* brace expansion, never before it: ``normpath`` reads a
    ``..`` as navigation wherever it sits, so ``{docs/../docs,zz}/**/*.md`` had its ``{docs``
    collapsed away and came back as ``docs,zz}/**/*.md`` -- a brace with no opening, which
    then expanded to nothing, matched nothing, and was allowed.

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

    When the pattern is absolute and the list entry is relative, neither form carries the
    other's root, so no suffix of the excluded path can line up with the pattern as written
    -- matching it directly against those suffixes let a whole-tree ``/abs/root/**`` sweep
    through, because the pattern's absolute segments never lined up with any relative
    suffix. ``_selects_across_forms`` recovers the case by discarding the pattern's literal
    leading directory -- the part naming the root we cannot see -- and matching what
    remains, which is form-independent and keeps the precision an unrelated absolute tree
    needs: ``/elsewhere/firmware/**/*.cs`` still misses a relative ``.md`` report because
    its remainder, ``**/*.cs``, cannot match a ``.md`` file.

    A brace list is expanded, and the pattern reaches the path if *any* alternative does.
    ``full_match`` has no brace support, so an unexpanded ``docs/**/*.{md,txt}`` matched
    nothing at all and was allowed -- a leak, in the syntax an agent reaches for to search
    two extensions at once. ``None`` from ``_expand_braces``, for a pattern past its bound,
    is treated as a match: over-approximating is the safe direction here, and this hook has
    a 5s timeout that fails open, so refusing to expand costs a denial rather than a leak.
    ``MATCH_BUDGET`` and ``MAX_DEPTH`` are the same trade one step later, since every
    alternative is tried against every suffix and it is that work, not the expansion, which
    the timeout actually feels.

    Each alternative is normalised and routed on its own leading ``/`` rather than the whole
    pattern's, since a brace at position zero can make them differ. Both are only ever
    additional ways to reach a match, which keeps every step of this predicate pointed at
    over-approximation.
    """
    segments = excluded.strip("/").split("/")
    alternatives = _expand_braces(pattern)
    if (
        alternatives is None
        or len(segments) > MAX_DEPTH
        or len(alternatives) * len(segments) > MATCH_BUDGET
    ):
        return True

    joined = ["/".join(segments[i:]) for i in range(len(segments))]
    relative = [PurePosixPath(suffix) for suffix in joined]
    absolute = [PurePosixPath(f"/{suffix}") for suffix in joined]

    for alternative in alternatives:
        alternative = posixpath.normpath(alternative)
        if not alternative.startswith("/"):
            candidates = relative
        elif excluded.startswith("/"):
            candidates = absolute
        elif _selects_across_forms(alternative, segments):
            return True
        else:
            continue
        if any(candidate.full_match(alternative) for candidate in candidates):
            return True
    return False


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
    if tool_name == "Grep" and selector.startswith("!"):
        # `!X` searches everything except `X`, so the excluded path is out of scope
        # only when `X` certainly covers it -- `_covers` under-approximates for exactly
        # that reason, unlike `_selects`, whose over-approximation would turn into an
        # allow once inverted. `Glob` has no negation syntax, so a leading `!` there is
        # an ordinary filename character and falls through to `_selects` below.
        return not _covers(selector.removeprefix("!"), excluded)
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
