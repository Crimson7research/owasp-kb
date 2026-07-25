"""SQLite connection factory."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(path: str | Path, *, load_vec: bool = False) -> sqlite3.Connection:
    """Open a connection with the pragmas this project relies on.

    Set ``load_vec`` to load the sqlite-vec extension. Raises if it is requested
    and unavailable, so callers can decide to degrade rather than fail silently.
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    if load_vec:
        import sqlite_vec

        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
    return conn


def vec_available(conn: sqlite3.Connection) -> bool:
    """True when the sqlite-vec extension is loaded in this connection."""
    try:
        conn.execute("SELECT vec_version()")
        return True
    except sqlite3.OperationalError:
        return False
