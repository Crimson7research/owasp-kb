"""BM25 retrieval over the FTS5 index."""

from __future__ import annotations

import re
import sqlite3

from owasp_kb.core.models import SearchHit
from owasp_kb.core.registry import get_pack
from owasp_kb.core.retrieval.base import HIT_SQL, row_to_hit

_TERM = re.compile(r"[\w']+")

# Stopwords are stripped because BM25 cannot distinguish them from signal:
# measured, "how do I bake sourdough bread" scored -12.28, better than a real
# query's third hit at -10.5, purely on how/do/I. A score threshold cannot fix
# that; removing the terms can.
_STOPWORDS = frozenset(
    """
a an and are as at be but by can could do does for from how i if in into is it me my of on or
should that the their them then there these they this to us was we what when where which who
why will with would you your
""".split()
)


def to_fts_query(text: str) -> str | None:
    """Turn free text into a safe FTS5 MATCH expression, or None if nothing usable.

    Every surviving term is quoted so FTS5 operators in user input cannot cause a
    syntax error, then OR-ed. Returns None when the query is entirely stopwords or
    punctuation, so the caller reports no match rather than matching on filler.
    """
    terms = [t for t in _TERM.findall(text) if t.lower() not in _STOPWORDS]
    if not terms:
        return None
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

        expression = to_fts_query(query)
        if expression is None:
            return []

        sql = HIT_SQL + " JOIN chunks_fts f ON f.rowid = c.id WHERE chunks_fts MATCH ?"
        params: list[object] = [expression]
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
