"""Ingest ASVS from the release flat.json into requirements plus one chunk each."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

from owasp_kb.core.chunking import estimate_tokens, slugify
from owasp_kb.core.registry import Pack, pack_id, upsert_pack

PACK_NAME = "asvs"
SOURCE_URL = "https://github.com/OWASP/ASVS"


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _clear_pack(conn: sqlite3.Connection, pid: int) -> None:
    """Remove this pack's rows so a rebuild cannot duplicate or leave stale content.

    Requirements reference chunks via a foreign key, so they must go first.
    Chunks are then deleted through the chunks table, not the FTS index, so the
    external-content sync triggers remove the matching postings.
    """
    conn.execute("DELETE FROM requirements WHERE pack_id = ?", (pid,))
    conn.execute(
        "DELETE FROM chunks WHERE section_id IN"
        " (SELECT s.id FROM sections s JOIN docs d ON d.id = s.doc_id WHERE d.pack_id = ?)",
        (pid,),
    )
    conn.execute(
        "DELETE FROM sections WHERE doc_id IN (SELECT id FROM docs WHERE pack_id = ?)", (pid,)
    )
    conn.execute("DELETE FROM docs WHERE pack_id = ?", (pid,))


def ingest_asvs(
    conn: sqlite3.Connection, flat_json_path: str | Path, *, version: str, license: str
) -> int:
    """Load every requirement. Returns the count ingested. Idempotent."""
    data = json.loads(Path(flat_json_path).read_text(encoding="utf-8"))
    requirements = data["requirements"]

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
    _clear_pack(conn, pid)

    doc_ids: dict[str, int] = {}
    section_ids: dict[str, int] = {}
    section_ord: dict[str, int] = {}

    for req in requirements:
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
            " section_id, section_name, text, level, chunk_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                pid,
                req["req_id"],
                chapter,
                req["chapter_name"],
                section,
                req["section_name"],
                req["req_description"],
                str(req["L"]),
                int(cur.lastrowid),
            ),
        )

    conn.commit()
    return len(requirements)
