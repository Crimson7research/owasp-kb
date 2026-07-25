import sqlite3

from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema

EXPECTED_TABLES = {
    "packs", "docs", "sections", "chunks", "chunks_fts", "requirements", "links",
}


def test_create_schema_creates_all_tables(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert EXPECTED_TABLES <= names


def test_create_schema_is_idempotent(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    create_schema(conn)  # must not raise


def test_fts_is_searchable_after_insert(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    conn.execute("INSERT INTO packs(name, type, version) VALUES ('p', 'corpus', '1')")
    conn.execute("INSERT INTO docs(pack_id, doc_key, title) VALUES (1, 'D', 'T')")
    conn.execute(
        "INSERT INTO sections(doc_id, anchor, heading_path, ord, depth)"
        " VALUES (1, 'a', 'T > A', 0, 2)"
    )
    conn.execute("INSERT INTO chunks(section_id, text, token_est) VALUES (1, 'brute force', 3)")
    hits = conn.execute("SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH 'brute'").fetchall()
    assert len(hits) == 1


def test_foreign_keys_are_enforced(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    try:
        conn.execute("INSERT INTO docs(pack_id, doc_key, title) VALUES (999, 'X', 'X')")
        conn.commit()
    except sqlite3.IntegrityError:
        return
    raise AssertionError("foreign key was not enforced")
