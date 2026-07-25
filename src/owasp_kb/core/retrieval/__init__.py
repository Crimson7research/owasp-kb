"""Retriever construction with explicit, reportable degradation."""

from __future__ import annotations

import logging
import sqlite3

from owasp_kb.core.retrieval.base import Retriever
from owasp_kb.core.retrieval.lexical import LexicalRetriever

log = logging.getLogger(__name__)

__all__ = ["LexicalRetriever", "Retriever", "build_retriever"]


def build_retriever(conn: sqlite3.Connection) -> Retriever:
    """Return a hybrid retriever when possible, else lexical.

    Every fallback is logged with its reason, and the chosen mode is exposed via
    the retriever's ``mode`` attribute so kb_info can report it. Degrading
    silently would leave an agent believing it had semantic search when it did
    not.
    """
    from owasp_kb.core.db import vec_available

    if not vec_available(conn):
        log.info("sqlite-vec not loaded; using lexical retrieval")
        return LexicalRetriever(conn)

    from owasp_kb.core.retrieval.hybrid import HybridRetriever, vectors_indexed

    if not vectors_indexed(conn):
        log.info("no vectors indexed; using lexical retrieval")
        return LexicalRetriever(conn)

    try:
        from owasp_kb.core.embed import Embedder

        embedder = Embedder()
    except (ImportError, FileNotFoundError) as exc:
        log.warning("embedder unavailable (%s); degrading to lexical retrieval", exc)
        return LexicalRetriever(conn)

    return HybridRetriever(conn, embedder)
