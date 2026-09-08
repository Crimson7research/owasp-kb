import sqlite3

import pytest

from owasp_kb.core.db import connect, finalize_for_readonly, is_wal_index
from owasp_kb.core.registry import PACK_TYPES
from owasp_kb.core.schema import create_schema

EXPECTED_TABLES = {
    "packs",
    "docs",
    "sections",
    "chunks",
    "chunks_fts",
    "requirements",
    "links",
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
    return conn.execute("SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?", (term,)).fetchall()


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


def test_serving_an_unfinalized_wal_index_raises_actionably(tmp_path):
    """immutable=1 can return silently wrong results for a file still being
    written, so serving a WAL index must fail loudly instead."""
    index = tmp_path / "kb.sqlite"
    conn = connect(index)
    create_schema(conn)
    _seed_one_chunk(conn, "brute force")
    conn.commit()
    conn.close()  # deliberately NOT finalized

    with pytest.raises(RuntimeError) as excinfo:
        connect(index, read_only=True)
    message = str(excinfo.value)
    assert "WAL" in message
    assert "finalize_for_readonly" in message, "the error must name the fix"


def test_is_wal_index_detects_both_states(tmp_path):
    index = tmp_path / "kb.sqlite"
    conn = connect(index)
    create_schema(conn)
    conn.commit()
    assert is_wal_index(index) is True
    finalize_for_readonly(conn)
    conn.close()
    assert is_wal_index(index) is False


def test_is_wal_index_on_a_missing_or_truncated_file_is_false(tmp_path):
    assert is_wal_index(tmp_path / "absent.sqlite") is False
    stub = tmp_path / "stub.sqlite"
    stub.write_bytes(b"short")
    assert is_wal_index(stub) is False


def test_read_only_open_handles_a_path_with_uri_metacharacters(tmp_path):
    """An unencoded '?' in the path silently opens a different database."""
    directory = tmp_path / "od? d"
    directory.mkdir()
    index = directory / "kb.sqlite"

    conn = connect(index)
    create_schema(conn)
    _seed_one_chunk(conn, "argon2id")
    conn.commit()
    finalize_for_readonly(conn)
    conn.close()

    served = connect(index, read_only=True)
    assert len(_matches(served, "argon2id")) == 1
    served.close()


def test_the_ddl_check_accepts_every_registry_pack_type():
    """The valid types were enumerated in the DDL, in PACK_TYPES, and in a test
    tuple. One of the three was widened. This binds the first two together so the
    next divergence is a red test rather than a failed ingest."""
    conn = connect(":memory:")
    create_schema(conn)
    for i, pack_type in enumerate(PACK_TYPES):
        conn.execute(
            "INSERT INTO packs (name, type, version) VALUES (?, ?, '1')",
            (f"probe-{i}", pack_type),
        )


def test_the_ddl_check_still_rejects_an_unknown_pack_type():
    """The check must stay a constraint, not become a comment."""
    conn = connect(":memory:")
    create_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO packs (name, type, version) VALUES ('probe', 'nonsense', '1')")


def test_catalogue_entries_table_exists_with_the_citation_fields():
    """A CWE citation needs kind, status and abstraction, not just an id.
    kind because a Category is not a Weakness and its graph is Has_Member rather
    than ChildOf; status because CWE-320 is Obsolete and eight ASVS requirements
    cite it, which is how an agent justifies departing from the mapping."""
    conn = connect(":memory:")
    create_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(catalogue_entries)")}
    assert cols == {
        "id",
        "pack_id",
        "entry_id",
        "kind",
        "name",
        "abstraction",
        "status",
        "description",
        "extended_description",
        "chunk_id",
    }


def test_requirements_carry_an_ordinal(tmp_path):
    """Ordering is data, not a parse of the id, so the column may not be null."""
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    columns = {
        row["name"]: row for row in conn.execute("PRAGMA table_info(requirements)").fetchall()
    }
    assert columns["ord"]["notnull"] == 1


def test_catalogue_entries_is_indexed_by_kind():
    """cwe_search filters by kind. Without the index that is a scan of 1,391 rows
    on every query; more importantly, an unasserted index is one nothing notices
    the loss of."""
    conn = connect(":memory:")
    create_schema(conn)
    names = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='catalogue_entries'"
        )
    }
    assert "idx_catalogue_kind" in names
