"""Split markdown into retrievable chunks without corrupting code blocks."""

from __future__ import annotations

import re
from collections import Counter

from owasp_kb.core.models import Chunk

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_SLUG_STRIP = re.compile(r"[^\w\s-]")

DEFAULT_MAX_TOKENS = 800
SPLIT_DEPTHS = (2, 3)


def slugify(heading: str) -> str:
    """GitHub-style anchor: lowercase, punctuation dropped, each space to a hyphen.

    GitHub does not collapse runs of whitespace: removing punctuation can leave
    adjacent spaces (e.g. "2.0 & OIDC" -> "20  oidc"), and each of those spaces
    becomes its own hyphen, producing a double hyphen.
    """
    text = _SLUG_STRIP.sub("", heading.strip().lower())
    return re.sub(r"\s", "-", text)


def estimate_tokens(text: str) -> int:
    """Cheap proxy: ~4 characters per token. Used only for split thresholds."""
    return max(1, len(text) // 4)


def _iter_lines_with_fence_state(text: str):
    """Yield (line, in_fence). A heading inside a fence is code, not structure."""
    in_fence = False
    fence_marker = ""
    for line in text.splitlines():
        match = _FENCE.match(line)
        if match:
            marker = match.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
                yield line, True
                continue
            if marker == fence_marker:
                yield line, True
                in_fence, fence_marker = False, ""
                continue
        yield line, in_fence


def _split_oversized(body: str, max_tokens: int) -> list[str]:
    """Split on blank lines, never inside a fence, keeping parts under max_tokens."""
    parts: list[str] = []
    current: list[str] = []
    current_tokens = 0
    buffer: list[str] = []
    for line, fenced in _iter_lines_with_fence_state(body):
        buffer.append(line)
        boundary = (not line.strip()) and not fenced
        if not boundary:
            continue
        block = "\n".join(buffer)
        buffer = []
        block_tokens = estimate_tokens(block)
        if current and current_tokens + block_tokens > max_tokens:
            parts.append("\n".join(current).strip())
            current, current_tokens = [], 0
        current.append(block)
        current_tokens += block_tokens
    if buffer:
        current.append("\n".join(buffer))
    tail = "\n".join(current).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p] or [body.strip()]


def chunk_markdown(text: str, *, title: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> list[Chunk]:
    """Split a markdown document at H2/H3 into chunks carrying their heading path."""
    sections: list[tuple[int, str, list[str]]] = [(1, title, [])]
    ancestors: dict[int, str] = {1: title}

    for line, fenced in _iter_lines_with_fence_state(text):
        heading = None if fenced else _HEADING.match(line)
        if heading is None:
            sections[-1][2].append(line)
            continue
        depth, heading_text = len(heading.group(1)), heading.group(2).strip()
        if depth == 1:
            ancestors = {1: heading_text or title}
            continue
        if depth not in SPLIT_DEPTHS:
            sections[-1][2].append(line)
            continue
        ancestors = {d: h for d, h in ancestors.items() if d < depth}
        ancestors[depth] = heading_text
        sections.append((depth, heading_text, []))

    # Assign anchors in document order, disambiguating repeats the way GitHub does
    # (-1, -2, ...). Uniqueness is mandatory, not cosmetic: sections carries
    # UNIQUE(doc_id, anchor), so colliding anchors would collapse distinct
    # subsections into one row and cite the wrong heading_path for their content.
    # Real corpus: 9 documents collide, one with 12 sections all slugifying to "do".
    seen: Counter[str] = Counter()
    anchors: list[str] = []
    for depth, heading_text, _ in sections:
        base = slugify(heading_text) if depth > 1 else slugify(title)
        seen[base] += 1
        anchors.append(base if seen[base] == 1 else f"{base}-{seen[base] - 1}")

    chunks: list[Chunk] = []
    path_stack: dict[int, str] = {1: title}
    ord_counter = 0
    for index, (depth, heading_text, lines) in enumerate(sections):
        body = "\n".join(lines).strip()
        path_stack = {d: h for d, h in path_stack.items() if d < depth}
        path_stack[depth] = heading_text
        heading_path = " > ".join(path_stack[d] for d in sorted(path_stack))
        if not body:
            continue
        anchor = anchors[index]
        for part in _split_oversized(body, max_tokens):
            chunks.append(
                Chunk(
                    anchor=anchor,
                    heading_path=heading_path,
                    depth=depth,
                    ord=ord_counter,
                    text=part,
                    token_est=estimate_tokens(part),
                )
            )
            ord_counter += 1
    return chunks
