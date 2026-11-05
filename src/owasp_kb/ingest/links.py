"""Populate the links edge table from upstream mapping files."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path

import yaml

from owasp_kb.ingest.aisvs_guidance import CURATED_GUIDANCE, CURATED_SOURCE
from owasp_kb.ingest.packs.aisvs import CHAPTER_GLOB as AISVS_CHAPTER_GLOB

log = logging.getLogger(__name__)

# AISVS links cheat sheets by their published .html URL, never the repo .md path
# IndexASVS.md uses, so _CS_LINK below matches none of them.
_AISVS_CS_LINK = re.compile(
    r"cheatsheetseries\.owasp\.org/cheatsheets/([A-Za-z0-9_]+_Cheat_Sheet)\.html"
)
_AISVS_CHAPTER = re.compile(r"^#\s+C(\d+)\s", re.MULTILINE)
_CS_TO_AISVS_CHAPTER = re.compile(r"github\.com/OWASP/AISVS/blob/[^)\s]*/0x10-C(\d+)-")
AISVS_REFERENCES = "AISVS chapter references"
CS_TO_AISVS = "cheat sheet links to AISVS"

_SECTION_HEADING = re.compile(r"^###\s+(V\d+\.\d+)\b")
_CHAPTER_HEADING = re.compile(r"^##\s+(V\d+):")
_CS_LINK = re.compile(r"\]\((?:.*/)?([A-Za-z0-9_]+_Cheat_Sheet)\.md\)")
_BE_KEY = re.compile(r"^v5\.0\.be-(\d+\.\d+\.\d+)$")
_RELEASE_REF = re.compile(r"v5\.0\.0-(\d+\.\d+\.\d+)")
_V4_REF = re.compile(r"v4\.0\.3-(\d+\.\d+\.\d+)")
_V5_KEY = re.compile(r"^v5\.0\.0-(\d+\.\d+\.\d+)$")
_NIST_ROW = re.compile(r"^\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|\s*([^|]*?)\s*\|")


def _insert(conn: sqlite3.Connection, rows: list[tuple], source: str) -> int:
    """Insert edges, ignoring duplicates so re-ingest is idempotent.

    Returns how many rows were actually new.
    """
    before = conn.execute("SELECT COUNT(*) FROM links WHERE source = ?", (source,)).fetchone()[0]
    conn.executemany(
        "INSERT OR IGNORE INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM links WHERE source = ?", (source,)).fetchone()[0]
    return after - before


def ingest_guidance_links(conn: sqlite3.Connection, index_asvs_path: str | Path) -> int:
    """Map ASVS chapters and sections to cheat sheets using IndexASVS.md.

    This is the cross-knowledge-base join, and OWASP maintains it upstream, so it
    is parsed rather than inferred.
    """
    text = Path(index_asvs_path).read_text(encoding="utf-8")
    rows: list[tuple] = []
    current = None
    for line in text.splitlines():
        section = _SECTION_HEADING.match(line)
        if section:
            current = section.group(1)
            continue
        chapter = _CHAPTER_HEADING.match(line)
        if chapter:
            current = chapter.group(1)
            continue
        if current is None:
            continue
        for doc_key in _CS_LINK.findall(line):
            rows.append(("asvs_section", current, "doc", doc_key, "guidance", "IndexASVS.md"))
    return _insert(conn, rows, "IndexASVS.md")


def _aisvs_reference_rows(chapters_dir: Path) -> list[tuple]:
    """Chapter-to-cheat-sheet edges from each AISVS chapter's own links."""
    rows: list[tuple] = []
    for path in sorted(chapters_dir.glob(AISVS_CHAPTER_GLOB)):
        text = path.read_text(encoding="utf-8")
        heading = _AISVS_CHAPTER.search(text)
        if heading is None:
            continue
        chapter = f"C{int(heading.group(1))}"
        for doc_key in dict.fromkeys(_AISVS_CS_LINK.findall(text)):
            rows.append(("aisvs_section", chapter, "doc", doc_key, "guidance", AISVS_REFERENCES))
    return rows


def _cheatsheet_aisvs_rows(cheatsheets_dir: Path) -> list[tuple]:
    """Chapter-to-cheat-sheet edges from cheat sheets that link an AISVS chapter."""
    rows: list[tuple] = []
    for path in sorted(cheatsheets_dir.glob("*_Cheat_Sheet.md")):
        text = path.read_text(encoding="utf-8")
        for number in dict.fromkeys(_CS_TO_AISVS_CHAPTER.findall(text)):
            rows.append(
                ("aisvs_section", f"C{int(number)}", "doc", path.stem, "guidance", CS_TO_AISVS)
            )
    return rows


def _curated_aisvs_rows() -> list[tuple]:
    return [
        ("aisvs_section", chapter, "doc", doc_key, "guidance", CURATED_SOURCE)
        for doc_key, chapters in CURATED_GUIDANCE.items()
        for chapter in chapters
    ]


def ingest_aisvs_guidance_links(
    conn: sqlite3.Connection, chapters_dir: str | Path, cheatsheets_dir: str | Path
) -> int:
    """Map AISVS chapters to cheat sheets. Run after both packs are ingested.

    No IndexASVS.md exists for AISVS, so the edges come from three places, in
    order of authority: the links in AISVS's own chapters, the links cheat
    sheets make to an AISVS chapter, and the reviewed map in aisvs_guidance.py.
    The links primary key keeps the first source for an edge stated twice.

    A curated chapter AISVS does not have is a ValueError: the map is ours, so
    a renumbering upstream must stop the build rather than strand edges. An
    upstream edge to an unknown chapter is dropped and logged instead.
    """
    known = {
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT r.chapter_id FROM requirements r"
            " JOIN packs p ON p.id = r.pack_id WHERE p.name = 'aisvs'"
        )
    }
    curated = _curated_aisvs_rows()
    unknown = sorted({row[1] for row in curated} - known)
    if unknown:
        raise ValueError(
            f"aisvs_guidance.CURATED_GUIDANCE names chapter(s) {', '.join(unknown)}, which "
            "the ingested AISVS release does not have; re-review the map against it"
        )
    upstream = _aisvs_reference_rows(Path(chapters_dir)) + _cheatsheet_aisvs_rows(
        Path(cheatsheets_dir)
    )
    kept = [row for row in upstream if row[1] in known]
    if len(kept) < len(upstream):
        log.warning(
            "dropped %d AISVS guidance link(s) to chapters the release does not have",
            len(upstream) - len(kept),
        )
    added = 0
    for source in (AISVS_REFERENCES, CS_TO_AISVS):
        added += _insert(conn, [row for row in kept if row[5] == source], source)
    return added + _insert(conn, curated, CURATED_SOURCE)


def load_be_to_release_map(mapping_path: str | Path) -> dict[str, str]:
    """Translate bleeding-edge requirement ids to pinned-release ids.

    Upstream publishes the CWE mapping keyed on bleeding-edge ids, and those are
    RENUMBERED relative to 5.0.0 -- measured, 0 of 345 are unchanged. For example
    v5.0.be-1.2.4 is v5.0.0-6.1.3. Stripping the prefix and keeping the number
    would therefore attach CWE-306 ("Missing Authentication for Critical
    Function") to V1.2.4, an encoding requirement, instead of V6.1.3. Every one of
    the 345 would be wrong, and each would look authoritative. So the translation
    must come from OWASP's own mapping file, never from string surgery.
    """
    raw = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
    translation: dict[str, str] = {}
    for be_key, value in raw.items():
        text = " ".join(str(v) for v in value.values()) if isinstance(value, dict) else str(value)
        match = _RELEASE_REF.search(text)
        if match:
            translation[str(be_key)] = f"V{match.group(1)}"
    return translation


def ingest_cwe_links(
    conn: sqlite3.Connection,
    mapping_path: str | Path,
    *,
    be_to_release_path: str | Path,
) -> tuple[int, int]:
    """Map requirements to CWEs, composed through the bleeding-edge translation.

    The CWE mapping is keyed on bleeding-edge ids, so each is translated to its
    pinned-release id first. Entries that do not translate, or that translate to a
    requirement absent from this release, are dropped and counted -- inserting one
    would fabricate a relationship. Returns (added, dropped).
    """
    raw = json.loads(Path(mapping_path).read_text(encoding="utf-8"))
    translation = load_be_to_release_map(be_to_release_path)
    known = {r[0] for r in conn.execute("SELECT req_id FROM requirements")}
    rows: list[tuple] = []
    dropped = 0
    source = "v5.0.be_cwe_mapping.json"

    for raw_key, cwes in raw.items():
        key = str(raw_key)
        # Accept an already-release-form id, else translate a bleeding-edge one.
        req_id = key if key in known else translation.get(key)
        if req_id is None or req_id not in known:
            dropped += 1
            continue
        for cwe in cwes if isinstance(cwes, list) else [cwes]:
            label = str(cwe) if str(cwe).upper().startswith("CWE-") else f"CWE-{cwe}"
            rows.append(("requirement", req_id, "cwe", label, "cwe", source))

    added = _insert(conn, rows, source)
    if dropped:
        log.warning(
            "dropped %d of %d CWE mapping entries that do not translate to a requirement "
            "in this ASVS release",
            dropped,
            len(raw),
        )
    return added, dropped


def ingest_supersedes_links(conn: sqlite3.Connection, mapping_path: str | Path) -> tuple[int, int]:
    """Map v5 requirements to the v4.0.3 requirements they replace.

    Upstream values are prose, e.g. 'MODIFIED, MOVED FROM v4.0.3-2.1.1, COVERS
    v4.0.3-2.1.6', so every v4 reference in the value is extracted. Requirements
    marked only ADDED have no predecessor and produce no edge.
    Returns (added, dropped).
    """
    raw = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
    known = {r[0] for r in conn.execute("SELECT req_id FROM requirements")}
    source = "mapping_v5.0.0_to_v4.0.3.yml"
    rows: list[tuple] = []
    dropped = 0

    for key, value in raw.items():
        match = _V5_KEY.match(str(key))
        if not match:
            continue
        req_id = f"V{match.group(1)}"
        if req_id not in known:
            dropped += 1
            continue
        text = " ".join(str(v) for v in value.values()) if isinstance(value, dict) else str(value)
        for v4 in dict.fromkeys(_V4_REF.findall(text)):
            rows.append(("requirement", req_id, "requirement", f"4.0.3-{v4}", "supersedes", source))

    added = _insert(conn, rows, source)
    if dropped:
        log.warning(
            "dropped %d v4 mapping entries whose v5 requirement ids are absent from this release",
            dropped,
        )
    return added, dropped


def ingest_nist_links(conn: sqlite3.Connection, nist_path: str | Path) -> tuple[int, int]:
    """Map requirements to NIST SP 800-63B sections, composed via the v4 mapping.

    nist.md is dated 07-Nov-2024 and keyed on v4.0.3 requirement ids, so a v5
    requirement reaches NIST only through its 'supersedes' edges. Run
    ingest_supersedes_links first. Coverage is partial by construction.
    Returns (added, skipped).
    """
    text = Path(nist_path).read_text(encoding="utf-8")
    source = "nist.md"

    v4_to_nist: dict[str, str] = {}
    for line in text.splitlines():
        match = _NIST_ROW.match(line)
        if not match:
            continue
        section = match.group(2).strip()
        if section:
            v4_to_nist[match.group(1)] = section

    edges = conn.execute("SELECT from_id, to_id FROM links WHERE rel = 'supersedes'").fetchall()
    if not edges:
        log.warning(
            "no 'supersedes' edges present, so %d NIST rows cannot be attached to v5 "
            "requirement ids; run ingest_supersedes_links first",
            len(v4_to_nist),
        )
        return 0, len(v4_to_nist)

    rows: list[tuple] = []
    matched_v4: set[str] = set()
    for edge in edges:
        v4_id = str(edge["to_id"]).removeprefix("4.0.3-")
        section = v4_to_nist.get(v4_id)
        if section is None:
            continue
        matched_v4.add(v4_id)
        rows.append(
            (
                "requirement",
                edge["from_id"],
                "nist",
                f"NIST SP 800-63B {section}",
                "nist",
                source,
            )
        )

    added = _insert(conn, rows, source)
    skipped = len(v4_to_nist) - len(matched_v4)
    log.info(
        "NIST links: %d edges added, %d nist.md rows unmatched (mapping is keyed on "
        "v4.0.3, so coverage is partial)",
        added,
        skipped,
    )
    return added, skipped
