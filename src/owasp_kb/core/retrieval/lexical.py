"""BM25 retrieval over the FTS5 index."""

from __future__ import annotations

import re
import sqlite3

from owasp_kb.core.models import SearchHit
from owasp_kb.core.registry import get_pack
from owasp_kb.core.retrieval.base import HIT_SQL, row_to_hit

_TERM = re.compile(r"[\w']+")


def to_fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression.

    Every term is quoted so FTS5 operators appearing in user input cannot cause a
    syntax error, then OR-ed so partial matches still rank. Queries reach this
    function from an AI agent relaying a user's words, so hostile syntax is the
    normal case, not an edge case.
    """
    terms = _TERM.findall(text)
    if not terms:
        return '""'
    return " OR ".join(f'"{t}"' for t in terms)


class LexicalRetriever:
    mode = "lexical"

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def search(
        self,
        query: str,
        *,
        pack: str | None = None,
        level: str | None = None,
        limit: int = 8,
    ) -> list[SearchHit]:
        if pack is not None:
            get_pack(self._conn, pack)  # raises KeyError listing available packs

        sql = HIT_SQL + " JOIN chunks_fts f ON f.rowid = c.id WHERE chunks_fts MATCH ?"
        params: list[object] = [to_fts_query(query)]
        if pack is not None:
            sql += " AND p.name = ?"
            params.append(pack)
        if level is not None:
            sql += " AND r.level = ?"
            params.append(level)
        sql += " ORDER BY bm25(chunks_fts) LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        # bm25() ranks negative-better; emit descending positive scores so
        # "higher is better" holds across every retriever.
        return [row_to_hit(row, score=float(-index)) for index, row in enumerate(rows)]
