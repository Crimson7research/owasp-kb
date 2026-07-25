import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import ingest_cwe_links, ingest_guidance_links
from owasp_kb.ingest.packs.asvs import ingest_asvs

ASVS_FIXTURE = "tests/fixtures/asvs_sample.flat.json"
INDEX_FIXTURE = "tests/fixtures/IndexASVS_sample.md"
CWE_FIXTURE = "tests/fixtures/cwe_mapping_sample.json"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    ingest_asvs(c, ASVS_FIXTURE, version="5.0.0", license="CC-BY-SA-4.0")
    return c


def test_guidance_links_map_asvs_sections_to_cheatsheets(conn):
    assert ingest_guidance_links(conn, INDEX_FIXTURE) == 3
    rows = conn.execute(
        "SELECT to_id FROM links WHERE from_id = 'V6.2' AND rel = 'guidance' ORDER BY to_id"
    ).fetchall()
    assert [r[0] for r in rows] == [
        "Authentication_Cheat_Sheet",
        "Credential_Stuffing_Prevention_Cheat_Sheet",
    ]


def test_guidance_links_record_their_source(conn):
    ingest_guidance_links(conn, INDEX_FIXTURE)
    source = conn.execute("SELECT DISTINCT source FROM links WHERE rel='guidance'").fetchone()[0]
    assert source == "IndexASVS.md"


def test_guidance_links_use_the_section_id_not_the_heading_text(conn):
    ingest_guidance_links(conn, INDEX_FIXTURE)
    ids = {r[0] for r in conn.execute("SELECT from_id FROM links WHERE rel='guidance'")}
    assert ids == {"V6.2", "V7.2"}


def test_guidance_to_id_is_a_doc_key_not_a_path(conn):
    """to_id must match docs.doc_key so owasp_related resolves to a real document."""
    ingest_guidance_links(conn, INDEX_FIXTURE)
    for (to_id,) in conn.execute("SELECT to_id FROM links WHERE rel='guidance'"):
        assert not to_id.endswith(".md")
        assert "/" not in to_id


def test_cwe_links_only_for_requirements_present_in_this_release(conn):
    added, dropped = ingest_cwe_links(conn, CWE_FIXTURE)
    assert added == 3
    assert dropped == 1  # V99.9.9 is not in the pinned release
    ids = {r[0] for r in conn.execute("SELECT from_id FROM links WHERE rel='cwe'")}
    assert "V99.9.9" not in ids


def test_cwe_targets_are_normalised(conn):
    ingest_cwe_links(conn, CWE_FIXTURE)
    rows = {r[0] for r in conn.execute("SELECT to_id FROM links WHERE rel='cwe'")}
    assert rows == {"CWE-521", "CWE-307"}


def test_cwe_accepts_values_already_prefixed(conn, tmp_path):
    mapping = tmp_path / "m.json"
    mapping.write_text('{"V6.2.1": ["CWE-521"]}')
    ingest_cwe_links(conn, mapping)
    assert {r[0] for r in conn.execute("SELECT to_id FROM links WHERE rel='cwe'")} == {"CWE-521"}


def test_cwe_accepts_a_bare_scalar_not_only_a_list(conn, tmp_path):
    mapping = tmp_path / "m.json"
    mapping.write_text('{"V6.2.1": 521}')
    ingest_cwe_links(conn, mapping)
    assert {r[0] for r in conn.execute("SELECT to_id FROM links WHERE rel='cwe'")} == {"CWE-521"}


def test_links_ingest_is_idempotent(conn):
    ingest_guidance_links(conn, INDEX_FIXTURE)
    ingest_guidance_links(conn, INDEX_FIXTURE)
    assert conn.execute("SELECT COUNT(*) FROM links WHERE rel='guidance'").fetchone()[0] == 3


def test_cwe_ingest_is_idempotent(conn):
    first, _ = ingest_cwe_links(conn, CWE_FIXTURE)
    second, _ = ingest_cwe_links(conn, CWE_FIXTURE)
    assert first == 3
    assert second == 0
    assert conn.execute("SELECT COUNT(*) FROM links WHERE rel='cwe'").fetchone()[0] == 3


def test_a_mapping_with_no_usable_entries_adds_nothing(conn, tmp_path):
    mapping = tmp_path / "m.json"
    mapping.write_text('{"V99.9.9": [1], "V88.8.8": [2]}')
    added, dropped = ingest_cwe_links(conn, mapping)
    assert added == 0
    assert dropped == 2
