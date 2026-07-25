"""Pack manifest access. Packs are knowledge bases; the type drives which tools apply."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

PACK_TYPES = ("checklist", "corpus")


@dataclass(frozen=True)
class Pack:
    name: str
    type: str
    version: str
    source_url: str | None = None
    commit_sha: str | None = None
    license: str | None = None
    fetched_at: str | None = None


def upsert_pack(conn: sqlite3.Connection, pack: Pack) -> None:
    """Insert or update a pack row. Validates the type before touching the database."""
    if pack.type not in PACK_TYPES:
        raise ValueError(f"unknown pack type {pack.type!r}; expected one of {PACK_TYPES}")
    conn.execute(
        """
        INSERT INTO packs (name, type, version, source_url, commit_sha, license, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            type=excluded.type, version=excluded.version, source_url=excluded.source_url,
            commit_sha=excluded.commit_sha, license=excluded.license,
            fetched_at=excluded.fetched_at
        """,
        (
            pack.name,
            pack.type,
            pack.version,
            pack.source_url,
            pack.commit_sha,
            pack.license,
            pack.fetched_at,
        ),
    )
    conn.commit()


def _row_to_pack(row: sqlite3.Row) -> Pack:
    return Pack(
        name=row["name"],
        type=row["type"],
        version=row["version"],
        source_url=row["source_url"],
        commit_sha=row["commit_sha"],
        license=row["license"],
        fetched_at=row["fetched_at"],
    )


def list_packs(conn: sqlite3.Connection) -> list[Pack]:
    rows = conn.execute("SELECT * FROM packs ORDER BY name").fetchall()
    return [_row_to_pack(r) for r in rows]


def get_pack(conn: sqlite3.Connection, name: str) -> Pack:
    """Fetch one pack.

    Raises KeyError naming the available packs rather than returning None: this
    message is handed to an AI agent by the MCP tool layer, so it must say what to
    do next instead of surfacing a bare lookup failure.
    """
    row = conn.execute("SELECT * FROM packs WHERE name = ?", (name,)).fetchone()
    if row is None:
        available = ", ".join(p.name for p in list_packs(conn)) or "(none)"
        raise KeyError(f"unknown pack {name!r}; available packs: {available}")
    return _row_to_pack(row)


def pack_id(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute("SELECT id FROM packs WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise KeyError(f"unknown pack {name!r}")
    return int(row["id"])
