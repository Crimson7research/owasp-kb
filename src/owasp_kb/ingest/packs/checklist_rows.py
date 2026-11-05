"""Row maintenance shared by the checklist pack ingests."""

from __future__ import annotations

import sqlite3


def clear_checklist_pack(conn: sqlite3.Connection, pid: int) -> None:
    """Remove a checklist pack's rows so a rebuild cannot duplicate or leave stale content.

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
