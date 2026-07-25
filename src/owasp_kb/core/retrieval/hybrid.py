"""Hybrid retrieval: BM25 and vector search fused with reciprocal rank fusion."""

from __future__ import annotations

import sqlite3
import struct

from owasp_kb.core.models import SearchHit
from owasp_kb.core.registry import get_pack
from owasp_kb.core.retrieval.base import HIT_SQL, row_to_hit
from owasp_kb.core.retrieval.lexical import to_fts_query

RRF_K = 60
CANDIDATES = 50

# Measured on the real index: relevant queries score 0.52-0.70, unrelated ones
# 0.90-1.03. Without a floor, vector search always returns a nearest neighbour,
# so an off-topic question came back with confident-looking security guidance.
MAX_VECTOR_DISTANCE = 0.80


def serialize_f32(vector: list[float]) -> bytes:
    """Pack a float list into sqlite-vec's compact binary format."""
    return struct.pack(f"{len(vector)}f", *vector)


def rrf_fuse[T](ranked_lists: list[list[T]], *, k: int = RRF_K) -> list[T]:
    """Fuse ranked lists by reciprocal rank; higher combined score ranks first.

    RRF is used instead of normalising scores because BM25 ranks and cosine
    distances are not on a comparable scale, and RRF needs no per-corpus tuning.
    Ties break by first appearance so results are deterministic.
    """
    scores: dict[T, float] = {}
    first_seen: dict[T, int] = {}
    for ranking in ranked_lists:
        for rank, item in enumerate(ranking):
            scores[item] = scores.get(item, 0.0) + 1.0 / (k + rank + 1)
            first_seen.setdefault(item, rank)
    return sorted(scores, key=lambda item: (-scores[item], first_seen[item]))


def index_vectors(conn: sqlite3.Connection, embedder, *, batch_size: int = 64) -> int:
    """Embed every chunk into chunks_vec. Requires sqlite-vec loaded. Idempotent."""
    from owasp_kb.core.schema import create_vec_schema

    create_vec_schema(conn, embedder.dim)
    conn.execute("DELETE FROM chunks_vec")
    rows = conn.execute("SELECT id, text FROM chunks ORDER BY id").fetchall()
    total = 0
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        vectors = embedder.encode([r["text"] for r in batch])
        conn.executemany(
            "INSERT INTO chunks_vec (chunk_id, embedding) VALUES (?, ?)",
            [(r["id"], serialize_f32(v)) for r, v in zip(batch, vectors, strict=True)],
        )
        total += len(batch)
    conn.commit()
    return total


def vectors_indexed(conn: sqlite3.Connection) -> bool:
    """True when a populated chunks_vec table exists."""
    try:
        return conn.execute("SELECT COUNT(*) FROM chunks_vec").fetchone()[0] > 0
    except sqlite3.OperationalError:
        return False


class HybridRetriever:
    mode = "hybrid"

    def __init__(self, conn: sqlite3.Connection, embedder) -> None:
        self._conn = conn
        self._embedder = embedder

    def _vector_chunk_ids(self, query: str, limit: int) -> list[int]:
        embedded = serialize_f32(self._embedder.encode_query(query))
        rows = self._conn.execute(
            "SELECT chunk_id, distance FROM chunks_vec"
            " WHERE embedding MATCH ? ORDER BY distance LIMIT ?",
            (embedded, limit),
        ).fetchall()
        return [
            int(r["chunk_id"]) for r in rows
            if float(r["distance"]) <= MAX_VECTOR_DISTANCE
        ]

    def _lexical_chunk_ids(self, query: str, limit: int) -> list[int]:
        expression = to_fts_query(query)
        if expression is None:
            return []
        rows = self._conn.execute(
            "SELECT c.id FROM chunks c JOIN chunks_fts f ON f.rowid = c.id"
            " WHERE chunks_fts MATCH ? ORDER BY bm25(chunks_fts) LIMIT ?",
            (expression, limit),
        ).fetchall()
        return [int(r[0]) for r in rows]

    def search(
        self,
        query: str,
        *,
        pack: str | None = None,
        level: str | None = None,
        limit: int = 8,
    ) -> list[SearchHit]:
        if pack is not None:
            get_pack(self._conn, pack)

        fused = rrf_fuse([
            self._lexical_chunk_ids(query, CANDIDATES),
            self._vector_chunk_ids(query, CANDIDATES),
        ])
        if not fused:
            return []

        placeholders = ",".join("?" * len(fused))
        sql = HIT_SQL + f" WHERE c.id IN ({placeholders})"
        params: list[object] = list(fused)
        if pack is not None:
            sql += " AND p.name = ?"
            params.append(pack)
        if level is not None:
            sql += " AND r.level = ?"
            params.append(level)

        by_id = {int(r["chunk_id"]): r for r in self._conn.execute(sql, params).fetchall()}
        hits: list[SearchHit] = []
        for rank, chunk_id in enumerate(fused):
            row = by_id.get(chunk_id)
            if row is None:  # filtered out by pack or level
                continue
            hits.append(row_to_hit(row, score=float(-rank)))
            if len(hits) == limit:
                break
        return hits
