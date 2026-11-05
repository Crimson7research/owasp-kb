"""Ingest ASVS from the release flat.json into requirements plus one chunk each."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

from owasp_kb.core.chunking import estimate_tokens, slugify
from owasp_kb.core.registry import Pack, pack_id, upsert_pack
from owasp_kb.ingest.packs.checklist_rows import clear_checklist_pack

PACK_NAME = "asvs"
SOURCE_URL = "https://github.com/OWASP/ASVS"


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _sort_key(req: dict) -> tuple[int, int, int]:
    """Chapter, section and requirement numbers, each as an integer.

    V6.2.1 -> (6, 2, 1). Derived from req_id rather than from chapter_id and
    section_id so all three segments come from one string and cannot disagree.
    """
    req_id = req["req_id"]
    # removeprefix, not lstrip: lstrip strips characters, not a prefix, and
    # would silently accept "VVV1.1.1". Every real ASVS id (345 of 345 in the
    # 5.0.0 release) is single-"V"-prefixed, so this states that intent rather
    # than changing behaviour.
    parts = req_id.removeprefix("V").split(".")
    if len(parts) != 3:
        raise ValueError(
            f"requirement {req_id!r} does not match the expected V<chapter>.<section>.<number> "
            "id shape; cannot compute its sort key"
        )
    chapter, section, number = parts
    return int(chapter), int(section), int(number)


def ingest_asvs(
    conn: sqlite3.Connection, flat_json_path: str | Path, *, version: str, license: str
) -> int:
    """Load every requirement. Returns the count ingested. Idempotent."""
    data = json.loads(Path(flat_json_path).read_text(encoding="utf-8"))
    # Sorted here rather than ordered in SQL later. The key is numeric per segment
    # for the reason the old ORDER BY was: lexically V10.1.1 precedes V2.1.1, which
    # silently corrupts any gap report that assumes ascending ids.
    requirements = sorted(data["requirements"], key=_sort_key)

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

    doc_ids: dict[str, int] = {}
    section_ids: dict[str, int] = {}
    section_ord: dict[str, int] = {}

    for ordinal, req in enumerate(requirements):
        chapter, section = req["chapter_id"], req["section_id"]

        if chapter not in doc_ids:
            cur = conn.execute(
                "INSERT INTO docs (pack_id, doc_key, title, source_url) VALUES (?, ?, ?, ?)",
                (pid, chapter, f"{chapter}: {req['chapter_name']}", SOURCE_URL),
            )
            doc_ids[chapter] = int(cur.lastrowid)
            section_ord[chapter] = 0

        if section not in section_ids:
            cur = conn.execute(
                "INSERT INTO sections (doc_id, anchor, heading_path, ord, depth)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    doc_ids[chapter],
                    slugify(section),
                    f"{req['chapter_name']} > {req['section_name']}",
                    section_ord[chapter],
                    2,
                ),
            )
            section_ids[section] = int(cur.lastrowid)
            section_ord[chapter] += 1

        text = (
            f"{req['chapter_name']} > {req['section_name']}\n"
            f"{req['req_id']} (L{req['L']}): {req['req_description']}"
        )
        cur = conn.execute(
            "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
            (section_ids[section], text, estimate_tokens(text)),
        )
        conn.execute(
            "INSERT INTO requirements (pack_id, req_id, chapter_id, chapter_name,"
            " section_id, section_name, text, level, ord, chunk_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                pid,
                req["req_id"],
                chapter,
                req["chapter_name"],
                section,
                req["section_name"],
                req["req_description"],
                str(req["L"]),
                ordinal,
                int(cur.lastrowid),
            ),
        )

    conn.commit()
    return len(requirements)
