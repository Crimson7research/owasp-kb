import sqlite3

import pytest

from owasp_kb.core.db import connect, finalize_for_readonly
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


def _seed_one_chunk(conn, text):
    conn.execute("INSERT INTO packs(name, type, version) VALUES ('p', 'corpus', '1')")
    conn.execute("INSERT INTO docs(pack_id, doc_key, title) VALUES (1, 'D', 'T')")
    conn.execute(
        "INSERT INTO sections(doc_id, anchor, heading_path, ord, depth)"
        " VALUES (1, 'a', 'T > A', 0, 2)"
    )
    conn.execute("INSERT INTO chunks(section_id, text, token_est) VALUES (1, ?, 2)", (text,))


def _matches(conn, term):
    return conn.execute(
        "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?", (term,)
    ).fetchall()


def test_deleting_a_chunk_removes_it_from_fts(tmp_path):
    """The chunks_ad trigger uses FTS5's 'delete' command form, which is easy to
    get wrong and leaves stale postings behind when it is."""
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    _seed_one_chunk(conn, "brute force")
    assert len(_matches(conn, "brute")) == 1
    conn.execute("DELETE FROM chunks WHERE id = 1")
    assert _matches(conn, "brute") == []


def test_updating_a_chunk_replaces_its_fts_entry(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    _seed_one_chunk(conn, "brute force")
    conn.execute("UPDATE chunks SET text = 'rate limiting' WHERE id = 1")
    assert _matches(conn, "brute") == [], "stale posting left after update"
    assert len(_matches(conn, "limiting")) == 1


def test_fts_integrity_check_passes_after_mutations(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    _seed_one_chunk(conn, "brute force")
    conn.execute("UPDATE chunks SET text = 'rate limiting' WHERE id = 1")
    conn.execute("INSERT INTO chunks(section_id, text, token_est) VALUES (1, 'argon2id', 1)")
    conn.execute("DELETE FROM chunks WHERE id = 1")
    conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('integrity-check')")


def test_finalized_index_opens_read_only_from_a_non_writable_directory(tmp_path):
    """A WAL index in a directory the process cannot write fails to open. The
    shipped image bakes the index into a root-owned directory and serves it as an
    unprivileged user, so this is the deployment case, not an edge case."""
    directory = tmp_path / "baked"
    directory.mkdir()
    index = directory / "kb.sqlite"

    conn = connect(index)
    create_schema(conn)
    _seed_one_chunk(conn, "brute force")
    conn.commit()
    finalize_for_readonly(conn)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    conn.close()

    directory.chmod(0o555)
    try:
        served = connect(index, read_only=True)
        assert len(_matches(served, "brute")) == 1
        served.close()
    finally:
        directory.chmod(0o755)


def test_read_only_connection_rejects_writes(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    finalize_for_readonly(conn)
    conn.close()

    served = connect(tmp_path / "kb.sqlite", read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        served.execute("INSERT INTO packs(name, type, version) VALUES ('x', 'corpus', '1')")
