"""Database schema. All DDL lives here."""

from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS packs (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL CHECK (type IN ('checklist', 'corpus', 'catalogue')),
    version     TEXT NOT NULL,
    source_url  TEXT,
    commit_sha  TEXT,
    license     TEXT,
    fetched_at  TEXT
);

CREATE TABLE IF NOT EXISTS docs (
    id          INTEGER PRIMARY KEY,
    pack_id     INTEGER NOT NULL REFERENCES packs(id),
    doc_key     TEXT NOT NULL,
    title       TEXT NOT NULL,
    source_path TEXT,
    source_url  TEXT,
    UNIQUE (pack_id, doc_key)
);

CREATE TABLE IF NOT EXISTS sections (
    id           INTEGER PRIMARY KEY,
    doc_id       INTEGER NOT NULL REFERENCES docs(id),
    anchor       TEXT NOT NULL,
    heading_path TEXT NOT NULL,
    ord          INTEGER NOT NULL,
    depth        INTEGER NOT NULL,
    UNIQUE (doc_id, anchor)
);

CREATE TABLE IF NOT EXISTS chunks (
    id         INTEGER PRIMARY KEY,
    section_id INTEGER NOT NULL REFERENCES sections(id),
    text       TEXT NOT NULL,
    token_est  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chunks_section ON chunks(section_id);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    text,
    content='chunks',
    content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
    INSERT INTO chunks_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.id, old.text);
    INSERT INTO chunks_fts(rowid, text) VALUES (new.id, new.text);
END;

CREATE TABLE IF NOT EXISTS requirements (
    id            INTEGER PRIMARY KEY,
    pack_id       INTEGER NOT NULL REFERENCES packs(id),
    req_id        TEXT NOT NULL,
    chapter_id    TEXT NOT NULL,
    chapter_name  TEXT NOT NULL,
    section_id    TEXT NOT NULL,
    section_name  TEXT NOT NULL,
    text          TEXT NOT NULL,
    level         TEXT NOT NULL,
    ord           INTEGER NOT NULL,
    chunk_id      INTEGER REFERENCES chunks(id),
    UNIQUE (pack_id, req_id)
);
CREATE INDEX IF NOT EXISTS idx_req_chapter ON requirements(pack_id, chapter_id);
CREATE INDEX IF NOT EXISTS idx_req_level ON requirements(pack_id, level);
CREATE INDEX IF NOT EXISTS idx_req_ord ON requirements(pack_id, ord);

CREATE TABLE IF NOT EXISTS catalogue_entries (
    id                   INTEGER PRIMARY KEY,
    pack_id              INTEGER NOT NULL REFERENCES packs(id),
    entry_id             TEXT NOT NULL,
    kind                 TEXT NOT NULL,
    name                 TEXT NOT NULL,
    abstraction          TEXT,
    status               TEXT NOT NULL,
    description          TEXT NOT NULL,
    extended_description TEXT NOT NULL DEFAULT '',
    chunk_id             INTEGER REFERENCES chunks(id),
    UNIQUE (pack_id, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_catalogue_kind ON catalogue_entries(pack_id, kind);

CREATE TABLE IF NOT EXISTS links (
    from_kind TEXT NOT NULL,
    from_id   TEXT NOT NULL,
    to_kind   TEXT NOT NULL,
    to_id     TEXT NOT NULL,
    rel       TEXT NOT NULL,
    source    TEXT NOT NULL,
    PRIMARY KEY (from_kind, from_id, to_kind, to_id, rel)
);
CREATE INDEX IF NOT EXISTS idx_links_from ON links(from_id, rel);
CREATE INDEX IF NOT EXISTS idx_links_to ON links(to_id, rel);
"""

VEC_SCHEMA_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_vec USING vec0(
    chunk_id INTEGER PRIMARY KEY,
    embedding FLOAT[{dim}]
);
"""


def create_schema(conn: sqlite3.Connection) -> None:
    """Create every non-vector table. Idempotent.

    ``executescript`` commits any pending transaction on the connection first.
    """
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def create_vec_schema(conn: sqlite3.Connection, dim: int) -> None:
    """Create the vector table. Requires sqlite-vec to be loaded.

    ``executescript`` commits any pending transaction on the connection first.
    """
    conn.executescript(VEC_SCHEMA_SQL.format(dim=dim))
    conn.commit()
