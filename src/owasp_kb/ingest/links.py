"""Populate the links edge table from upstream mapping files."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path

log = logging.getLogger(__name__)

_SECTION_HEADING = re.compile(r"^###\s+(V\d+\.\d+)\b")
_CHAPTER_HEADING = re.compile(r"^##\s+(V\d+):")
_CS_LINK = re.compile(r"\]\((?:.*/)?([A-Za-z0-9_]+_Cheat_Sheet)\.md\)")


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


def ingest_cwe_links(conn: sqlite3.Connection, mapping_path: str | Path) -> tuple[int, int]:
    """Map requirements to CWEs, dropping ids absent from the ingested release.

    Upstream only publishes a bleeding-edge CWE mapping, so some requirement ids
    will not exist in a pinned release. Inserting those would fabricate a
    relationship, so they are dropped and counted. Returns (added, dropped).
    """
    raw = json.loads(Path(mapping_path).read_text(encoding="utf-8"))
    known = {r[0] for r in conn.execute("SELECT req_id FROM requirements")}
    rows: list[tuple] = []
    dropped = 0
    source = "v5.0.be_cwe_mapping.json"
    for req_id, cwes in raw.items():
        if req_id not in known:
            dropped += 1
            continue
        for cwe in cwes if isinstance(cwes, list) else [cwes]:
            label = str(cwe) if str(cwe).upper().startswith("CWE-") else f"CWE-{cwe}"
            rows.append(("requirement", req_id, "cwe", label, "cwe", source))
    added = _insert(conn, rows, source)
    if dropped:
        log.warning(
            "dropped %d CWE mapping entries whose requirement ids are absent from this "
            "ASVS release; the mapping upstream is bleeding-edge",
            dropped,
        )
    return added, dropped
