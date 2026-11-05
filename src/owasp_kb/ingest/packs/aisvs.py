"""Ingest AISVS from the pinned release's chapter Markdown.

AISVS ships no machine-readable release asset -- the only one at v1.01 is a PDF
-- so the frozen ``1.01/en/0x10-C*.md`` chapters are parsed instead. Each holds
one ``# C<n>`` chapter heading, a Control Objective, ``## C<n>.<m>`` sections
with a requirement table each, and a References list. The shape is ASVS's:
chapter, section, numbered requirement, cumulative levels 1-3.

Ids keep the upstream ``C`` prefix (``C10.2.2``), which is what AISVS's own
``v1.01-Cx.y.z`` citation form uses. It also keeps them apart from ASVS's
``V10.2.2`` in the links table, whose ids carry no pack.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from owasp_kb.core.chunking import estimate_tokens, slugify, split_prose
from owasp_kb.core.registry import Pack, pack_id, upsert_pack
from owasp_kb.ingest.packs.checklist_rows import clear_checklist_pack

PACK_NAME = "aisvs"
SOURCE_URL = "https://github.com/OWASP/AISVS"
CHAPTER_GLOB = "0x10-C*.md"

# 1.01 keeps a removed requirement's number as a row with this text and no
# level, so the numbering of its neighbours does not move.
REMOVED_TEXT = "Requirement removed."
OBJECTIVE_HEADING = "Control Objective"

_CHAPTER = re.compile(r"^#\s+C(\d+)\s+(.+?)\s*$")
_SECTION = re.compile(r"^##\s+C(\d+\.\d+)\s+(.+?)\s*$")
_OTHER_H2 = re.compile(r"^##\s+(.+?)\s*$")
_ROW = re.compile(r"^\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|\s*(.*?)\s*\|\s*(\S*)\s*\|\s*$")
_TABLE_LINE = re.compile(r"^\|")
_RULE = re.compile(r"^-{3,}$")


@dataclass(frozen=True)
class Requirement:
    req_id: str
    level: str
    text: str


@dataclass
class Section:
    section_id: str
    name: str
    prose: list[str] = field(default_factory=list)
    requirements: list[Requirement] = field(default_factory=list)


@dataclass
class Chapter:
    chapter_id: str
    name: str
    number: int
    objective: list[str] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)

    @property
    def requirement_count(self) -> int:
        return sum(len(s.requirements) for s in self.sections)


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _parse_row(match: re.Match[str], section: Section | None, source: str) -> Requirement | None:
    """One table row as a requirement, or None for a removed-requirement tombstone."""
    number, description, level = match.groups()
    if section is None:
        raise ValueError(f"{source}: requirement {number} appears before any section heading")
    if not f"C{number}".startswith(f"{section.section_id}."):
        raise ValueError(f"{source}: requirement {number} sits under section {section.section_id}")
    if not level:
        if description == REMOVED_TEXT:
            return None
        raise ValueError(f"{source}: requirement {number} has no level and is not '{REMOVED_TEXT}'")
    if level not in ("1", "2", "3"):
        raise ValueError(f"{source}: requirement {number} has level {level!r}, expected 1-3")
    return Requirement(req_id=f"C{number}", level=level, text=description.replace("**", ""))


def _prose_target(chapter: Chapter, heading: str | None) -> list[str] | None:
    """Where a prose line belongs: the objective, the open section, or nowhere."""
    if heading == OBJECTIVE_HEADING:
        return chapter.objective
    if heading is None and chapter.sections:
        return chapter.sections[-1].prose
    return None


def _read_chapter_heading(lines: list[str], source: str) -> Chapter:
    for line in lines:
        match = _CHAPTER.match(line)
        if match:
            number = int(match.group(1))
            return Chapter(chapter_id=f"C{number}", name=match.group(2), number=number)
    raise ValueError(f"{source}: no '# C<n>' chapter heading")


def parse_chapter(text: str, source: str) -> Chapter:
    """Parse one chapter file. Raises ValueError naming the file on any surprise."""
    lines = text.splitlines()
    chapter = _read_chapter_heading(lines, source)
    # The open non-section ## heading ("Control Objective", "References"), or
    # None while a C<n>.<m> section is open.
    other_heading: str | None = None
    for line in lines:
        section = _SECTION.match(line)
        if section:
            chapter.sections.append(Section(f"C{section.group(1)}", section.group(2)))
            other_heading = None
            continue
        other = _OTHER_H2.match(line)
        if other:
            other_heading = other.group(1)
            continue
        row = _ROW.match(line)
        if row:
            open_section = chapter.sections[-1] if chapter.sections else None
            requirement = _parse_row(row, open_section, source)
            if requirement is not None and open_section is not None:
                open_section.requirements.append(requirement)
            continue
        _collect_prose(chapter, other_heading, line)
    return chapter


def _collect_prose(chapter: Chapter, heading: str | None, line: str) -> None:
    stripped = line.strip()
    if not stripped or _TABLE_LINE.match(stripped) or _RULE.match(stripped):
        return
    if stripped.startswith("# "):
        return
    target = _prose_target(chapter, heading)
    if target is not None:
        target.append(stripped)


def load_chapters(chapters_dir: str | Path) -> list[Chapter]:
    """Every chapter under ``chapters_dir``, in chapter-number order."""
    paths = sorted(Path(chapters_dir).glob(CHAPTER_GLOB))
    if not paths:
        raise ValueError(
            f"no AISVS chapter files matching {CHAPTER_GLOB!r} under {chapters_dir}; "
            "expected the 1.01/en/ chapters sources.lock.yml lists for aisvs"
        )
    chapters = [parse_chapter(p.read_text(encoding="utf-8"), p.name) for p in paths]
    empty = [c.chapter_id for c in chapters if not c.requirement_count]
    if empty:
        raise ValueError(f"AISVS chapter(s) {', '.join(empty)} hold no requirement rows")
    return sorted(chapters, key=lambda c: c.number)


def _insert_doc(conn: sqlite3.Connection, pid: int, chapter: Chapter) -> int:
    cur = conn.execute(
        "INSERT INTO docs (pack_id, doc_key, title, source_url) VALUES (?, ?, ?, ?)",
        (pid, chapter.chapter_id, f"{chapter.chapter_id}: {chapter.name}", SOURCE_URL),
    )
    return int(cur.lastrowid)


def _insert_section(
    conn: sqlite3.Connection, doc_id: int, anchor: str, heading_path: str, ordinal: int
) -> int:
    cur = conn.execute(
        "INSERT INTO sections (doc_id, anchor, heading_path, ord, depth) VALUES (?, ?, ?, ?, ?)",
        (doc_id, anchor, heading_path, ordinal, 2),
    )
    return int(cur.lastrowid)


def _insert_prose(
    conn: sqlite3.Connection, section_id: int, heading: str, prose: list[str]
) -> None:
    """Prose as chunks with no requirement row, split like any oversized section."""
    if not prose:
        return
    for part in split_prose(f"{heading}\n" + "\n\n".join(prose)):
        conn.execute(
            "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
            (section_id, part, estimate_tokens(part)),
        )


def _insert_requirement(
    conn: sqlite3.Connection,
    pid: int,
    placement: tuple[Chapter, Section, int],
    requirement: Requirement,
    ordinal: int,
) -> None:
    chapter, section, section_row = placement
    text = (
        f"{chapter.name} > {section.name}\n"
        f"{requirement.req_id} (L{requirement.level}): {requirement.text}"
    )
    cur = conn.execute(
        "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
        (section_row, text, estimate_tokens(text)),
    )
    conn.execute(
        "INSERT INTO requirements (pack_id, req_id, chapter_id, chapter_name,"
        " section_id, section_name, text, level, ord, chunk_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            pid,
            requirement.req_id,
            chapter.chapter_id,
            chapter.name,
            section.section_id,
            section.name,
            requirement.text,
            requirement.level,
            ordinal,
            int(cur.lastrowid),
        ),
    )


def _write_chapter(conn: sqlite3.Connection, pid: int, chapter: Chapter, ordinal: int) -> int:
    """Insert one chapter's doc, sections, prose and requirements. Returns the next ordinal."""
    doc_id = _insert_doc(conn, pid, chapter)
    if chapter.objective:
        objective_row = _insert_section(
            conn, doc_id, slugify(OBJECTIVE_HEADING), f"{chapter.name} > {OBJECTIVE_HEADING}", 0
        )
        _insert_prose(conn, objective_row, chapter.name, chapter.objective)
    for position, section in enumerate(chapter.sections, start=1):
        heading = f"{chapter.name} > {section.name}"
        section_row = _insert_section(conn, doc_id, slugify(section.section_id), heading, position)
        _insert_prose(conn, section_row, heading, section.prose)
        for requirement in section.requirements:
            _insert_requirement(conn, pid, (chapter, section, section_row), requirement, ordinal)
            ordinal += 1
    return ordinal


def ingest_aisvs(
    conn: sqlite3.Connection, chapters_dir: str | Path, *, version: str, license: str
) -> int:
    """Load every live requirement. Returns the count ingested. Idempotent.

    Parses every chapter before writing anything, so a malformed chapter leaves
    no pack row behind.
    """
    chapters = load_chapters(chapters_dir)
    upsert_pack(
        conn,
        Pack(
            name=PACK_NAME,
            type="checklist",
            version=version,
            source_url=SOURCE_URL,
            commit_sha=None,
            license=license,
            fetched_at=_now(),
        ),
    )
    pid = pack_id(conn, PACK_NAME)
    clear_checklist_pack(conn, pid)

    ordinal = 0
    for chapter in chapters:
        ordinal = _write_chapter(conn, pid, chapter, ordinal)

    conn.commit()
    return ordinal
