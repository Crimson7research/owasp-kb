"""Populate the links edge table from upstream mapping files."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

_SECTION_HEADING = re.compile(r"^###\s+(V\d+\.\d+)\b")
_CHAPTER_HEADING = re.compile(r"^##\s+(V\d+):")
_CS_LINK = re.compile(r"\]\((?:.*/)?([A-Za-z0-9_]+_Cheat_Sheet)\.md\)")
_BE_KEY = re.compile(r"^v5\.0\.be-(\d+\.\d+\.\d+)$")
_RELEASE_REF = re.compile(r"v5\.0\.0-(\d+\.\d+\.\d+)")


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
