"""Retriever construction."""

from __future__ import annotations

import sqlite3

from owasp_kb.core.retrieval.base import Retriever
from owasp_kb.core.retrieval.lexical import LexicalRetriever

__all__ = ["LexicalRetriever", "Retriever", "build_retriever"]


def build_retriever(conn: sqlite3.Connection) -> Retriever:
    """Build the best retriever this index supports.

    Hybrid support is added in a later task; for now this is always lexical.
    """
    return LexicalRetriever(conn)
