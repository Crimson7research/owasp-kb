"""Ingest the Cheat Sheet Series markdown into docs, sections and chunks."""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from pathlib import Path

from owasp_kb.core.chunking import chunk_markdown
from owasp_kb.core.registry import Pack, pack_id, upsert_pack

PACK_NAME = "cheatsheets"
SOURCE_URL = "https://github.com/OWASP/CheatSheetSeries"
_H1 = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _title_of(text: str, fallback: str) -> str:
    match = _H1.search(text)
    return match.group(1).strip() if match else fallback.replace("_", " ")


def _clear_pack(conn: sqlite3.Connection, pid: int) -> None:
    """Remove this pack's rows so a rebuild cannot duplicate or leave stale content.

    A corpus pack has no requirements rows, so chunks -> sections -> docs is safe.
    Chunks are deleted through the chunks table, never chunks_fts, so the
    external-content sync triggers remove the matching postings.
    """
    conn.execute(
        "DELETE FROM chunks WHERE section_id IN"
        " (SELECT s.id FROM sections s JOIN docs d ON d.id = s.doc_id WHERE d.pack_id = ?)",
        (pid,),
    )
    conn.execute(
        "DELETE FROM sections WHERE doc_id IN (SELECT id FROM docs WHERE pack_id = ?)", (pid,)
    )
    conn.execute("DELETE FROM docs WHERE pack_id = ?", (pid,))


def ingest_cheatsheets(
    conn: sqlite3.Connection,
    cheatsheets_dir: str | Path,
    *,
    version: str,
    commit_sha: str,
    license: str,
) -> int:
    """Load every ``*.md`` in the directory. Returns the document count. Idempotent."""
    directory = Path(cheatsheets_dir)
    files = sorted(directory.glob("*.md"))
    if not files:
        raise FileNotFoundError(
            f"no markdown files under {directory}; expected the Cheat Sheet Series "
            "'cheatsheets/' directory from a fetched corpus"
        )

    upsert_pack(
        conn,
        Pack(
            name=PACK_NAME,
            type="corpus",
            version=version,
            source_url=SOURCE_URL,
            commit_sha=commit_sha,
            license=license,
            fetched_at=_now(),
        ),
    )
    pid = pack_id(conn, PACK_NAME)
    _clear_pack(conn, pid)

    for path in files:
        doc_key = path.stem
        text = path.read_text(encoding="utf-8")
        title = _title_of(text, doc_key)
        cur = conn.execute(
            "INSERT INTO docs (pack_id, doc_key, title, source_path, source_url)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                pid,
                doc_key,
                title,
                f"cheatsheets/{path.name}",
                f"{SOURCE_URL}/blob/{commit_sha}/cheatsheets/{path.name}",
            ),
        )
        doc_id = int(cur.lastrowid)

        section_ids: dict[str, int] = {}
        for chunk in chunk_markdown(text, title=title):
            if chunk.anchor not in section_ids:
                scur = conn.execute(
                    "INSERT INTO sections (doc_id, anchor, heading_path, ord, depth)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (doc_id, chunk.anchor, chunk.heading_path, chunk.ord, chunk.depth),
                )
                section_ids[chunk.anchor] = int(scur.lastrowid)
            conn.execute(
                "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
                (section_ids[chunk.anchor], chunk.text, chunk.token_est),
            )

    conn.commit()
    return len(files)
