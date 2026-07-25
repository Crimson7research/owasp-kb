import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.registry import get_pack
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.asvs import ingest_asvs

FIXTURE = "tests/fixtures/asvs_sample.flat.json"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


def _ingest(conn):
    return ingest_asvs(conn, FIXTURE, version="5.0.0", license="CC-BY-SA-4.0")


def test_ingests_every_requirement(conn):
    assert _ingest(conn) == 3
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 3


def test_registers_pack_as_checklist(conn):
    _ingest(conn)
    pack = get_pack(conn, "asvs")
    assert pack.type == "checklist"
    assert pack.version == "5.0.0"
    assert pack.license == "CC-BY-SA-4.0"


def test_each_requirement_gets_a_searchable_chunk(conn):
    _ingest(conn)
    hits = conn.execute(
        "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH 'passwords'"
    ).fetchall()
    assert len(hits) >= 2


def test_chunk_text_carries_chapter_and_section_context(conn):
    _ingest(conn)
    row = conn.execute(
        "SELECT c.text FROM requirements r JOIN chunks c ON c.id = r.chunk_id"
        " WHERE r.req_id = 'V6.2.1'"
    ).fetchone()
    assert "Authentication" in row["text"]
    assert "Password Security" in row["text"]
    assert "8 characters" in row["text"]
    assert "V6.2.1" in row["text"]


def test_levels_are_preserved_as_strings(conn):
    _ingest(conn)
    levels = dict(conn.execute("SELECT req_id, level FROM requirements"))
    assert levels["V6.2.1"] == "1"
    assert levels["V6.2.2"] == "2"


def test_one_doc_per_chapter_and_one_section_row_per_section(conn):
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM sections").fetchone()[0] == 2


def test_doc_key_is_the_chapter_id(conn):
    _ingest(conn)
    keys = {r[0] for r in conn.execute("SELECT doc_key FROM docs")}
    assert keys == {"V1", "V6"}


def test_every_requirement_links_to_a_real_chunk(conn):
    _ingest(conn)
    orphans = conn.execute(
        "SELECT req_id FROM requirements WHERE chunk_id IS NULL"
        " OR chunk_id NOT IN (SELECT id FROM chunks)"
    ).fetchall()
    assert orphans == []


def test_reingest_is_idempotent(conn):
    _ingest(conn)
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == 3


def test_reingest_leaves_no_stale_fts_rows(conn):
    """chunks_fts is external-content; a rebuild that bypassed the delete
    triggers would leave orphaned postings that still match."""
    _ingest(conn)
    _ingest(conn)
    fts_rows = conn.execute("SELECT COUNT(*) FROM chunks_fts").fetchone()[0]
    chunk_rows = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    assert fts_rows == chunk_rows
    conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('integrity-check')")


def test_reingest_after_content_change_drops_removed_requirements(conn, tmp_path):
    """A future release with fewer requirements must not leave the old ones behind."""
    _ingest(conn)
    smaller = tmp_path / "smaller.json"
    smaller.write_text(
        '{"requirements": [{"chapter_id": "V1", "chapter_name": "Encoding and Sanitization",'
        ' "section_id": "V1.1", "section_name": "Arch", "req_id": "V1.1.1",'
        ' "req_description": "only one left.", "L": "2"}]}'
    )
    assert ingest_asvs(conn, smaller, version="5.1.0", license="CC-BY-SA-4.0") == 1
    ids = {r[0] for r in conn.execute("SELECT req_id FROM requirements")}
    assert ids == {"V1.1.1"}
    assert get_pack(conn, "asvs").version == "5.1.0"


def test_fetched_at_is_recorded(conn):
    _ingest(conn)
    assert get_pack(conn, "asvs").fetched_at
