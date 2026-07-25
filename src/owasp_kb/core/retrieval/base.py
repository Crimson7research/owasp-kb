"""Retriever contract and the shared hit-projection SQL."""

from __future__ import annotations

from typing import Protocol

from owasp_kb.core.models import SearchHit

HIT_SQL = """
SELECT
    c.id            AS chunk_id,
    c.text          AS text,
    s.anchor        AS anchor,
    s.heading_path  AS heading_path,
    d.doc_key       AS doc_key,
    p.name          AS pack,
    p.version       AS pack_version,
    r.req_id        AS req_id,
    r.level         AS level
FROM chunks c
JOIN sections s ON s.id = c.section_id
JOIN docs d     ON d.id = s.doc_id
JOIN packs p    ON p.id = d.pack_id
LEFT JOIN requirements r ON r.chunk_id = c.id
"""


def row_to_hit(row, score: float) -> SearchHit:
    """Project a HIT_SQL row into a SearchHit.

    Shared so the lexical and hybrid retrievers cannot drift in what they return.
    """
    return SearchHit(
        pack=row["pack"],
        pack_version=row["pack_version"],
        req_id=row["req_id"],
        doc_key=row["doc_key"],
        anchor=row["anchor"],
        heading_path=row["heading_path"],
        text=row["text"],
        score=score,
    )


class Retriever(Protocol):
    mode: str

    def search(
        self,
        query: str,
        *,
        pack: str | None = None,
        level: str | None = None,
        limit: int = 8,
    ) -> list[SearchHit]:
        """Return hits ordered best-first. Empty list when nothing matches."""
        ...
