import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import ingest_nist_links, ingest_supersedes_links
from owasp_kb.ingest.packs.asvs import ingest_asvs

MAPPING = "tests/fixtures/mapping_v5_to_v4_sample.yml"
NIST = "tests/fixtures/nist_sample.md"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    ingest_asvs(c, "tests/fixtures/asvs_sample.flat.json", version="5.0.0", license="CC-BY-SA-4.0")
    return c


def test_supersedes_links_extract_v4_ids(conn):
    added, dropped = ingest_supersedes_links(conn, MAPPING)
    rows = {
        r[0]
        for r in conn.execute(
            "SELECT to_id FROM links WHERE from_id = 'V6.2.1' AND rel = 'supersedes'"
        )
    }
    assert rows == {"4.0.3-2.1.1"}
    assert added >= 3


def test_supersedes_captures_every_v4_reference_in_the_prose(conn):
    """The value is prose: 'MOVED FROM v4.0.3-2.1.5, COVERS v4.0.3-2.1.6'."""
    ingest_supersedes_links(conn, MAPPING)
    rows = {
        r[0]
        for r in conn.execute(
            "SELECT to_id FROM links WHERE from_id = 'V6.2.2' AND rel = 'supersedes'"
        )
    }
    assert rows == {"4.0.3-2.1.5", "4.0.3-2.1.6"}


def test_added_requirements_produce_no_supersedes_edge(conn):
    ingest_supersedes_links(conn, MAPPING)
    assert (
        conn.execute(
            "SELECT 1 FROM links WHERE from_id = 'V1.1.1' AND rel = 'supersedes'"
        ).fetchall()
        == []
    )


def test_supersedes_drops_requirements_absent_from_this_release(conn):
    _, dropped = ingest_supersedes_links(conn, MAPPING)
    assert dropped == 1
    ids = {r[0] for r in conn.execute("SELECT from_id FROM links WHERE rel='supersedes'")}
    assert "V99.9.9" not in ids


def test_supersedes_records_its_source(conn):
    ingest_supersedes_links(conn, MAPPING)
    source = conn.execute("SELECT DISTINCT source FROM links WHERE rel='supersedes'").fetchone()[0]
    assert "v4.0.3" in source


def test_nist_links_compose_through_the_v4_mapping(conn):
    ingest_supersedes_links(conn, MAPPING)
    added, skipped = ingest_nist_links(conn, NIST)
    rows = {
        r[0]
        for r in conn.execute("SELECT to_id FROM links WHERE from_id = 'V6.2.1' AND rel = 'nist'")
    }
    assert rows == {"NIST SP 800-63B 5.1.1.2"}
    assert added >= 1


def test_nist_ignores_rows_with_an_empty_section(conn):
    ingest_supersedes_links(conn, MAPPING)
    ingest_nist_links(conn, NIST)
    rows = {
        r[0]
        for r in conn.execute("SELECT to_id FROM links WHERE from_id = 'V6.2.2' AND rel = 'nist'")
    }
    assert rows == {"NIST SP 800-63B 5.1.1.2"}  # from 2.1.5 only; 2.1.6 is blank
    assert not any(
        t.strip().endswith("800-63B")
        for (t,) in conn.execute("SELECT to_id FROM links WHERE rel='nist'")
    ), "an empty NIST cell must not become an empty target"


def test_nist_without_supersedes_edges_adds_nothing_and_says_so(conn):
    added, skipped = ingest_nist_links(conn, NIST)
    assert added == 0
    assert skipped > 0, "must report that it could not compose the join"


def test_nist_does_not_attach_to_a_v4_id_directly(conn):
    """nist.md is keyed on v4.0.3 ids; storing those as from_id would be wrong."""
    ingest_supersedes_links(conn, MAPPING)
    ingest_nist_links(conn, NIST)
    ids = {r[0] for r in conn.execute("SELECT from_id FROM links WHERE rel='nist'")}
    assert all(i.startswith("V") for i in ids)
    assert "2.1.1" not in ids


def test_mapping_ingests_are_idempotent(conn):
    ingest_supersedes_links(conn, MAPPING)
    ingest_nist_links(conn, NIST)
    before = conn.execute("SELECT COUNT(*) FROM links").fetchone()[0]
    ingest_supersedes_links(conn, MAPPING)
    ingest_nist_links(conn, NIST)
    assert conn.execute("SELECT COUNT(*) FROM links").fetchone()[0] == before
