import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.integrity import run_checks
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import ingest_guidance_links
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.ingest.packs.cwe import ingest_cwe


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    ingest_asvs(c, "tests/fixtures/asvs_sample.flat.json", version="5.0.0", license="CC-BY-SA-4.0")
    ingest_cheatsheets(
        c,
        "tests/fixtures/cheatsheets",
        version="20260724",
        commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
        license="CC-BY-SA-4.0",
    )
    return c


def _add_edges(conn, rel, count, source="test"):
    conn.executemany(
        "INSERT OR IGNORE INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('requirement', ?, 'x', ?, ?, ?)",
        [(f"V1.1.{i}", f"T{i}", rel, source) for i in range(count)],
    )
    conn.commit()


def _ingest_cwe_fixture(conn):
    """Populate the catalogue so the CWE-aware checks are active."""
    ingest_cwe(conn, "tests/fixtures/cwec_sample.xml", version="4.20", license="LicenseRef-CWE-TOU")


def _all_rels(conn):
    """Satisfy the relationship-coverage checks so other assertions are isolated."""
    ingest_guidance_links(conn, "tests/fixtures/IndexASVS_sample.md")
    _add_edges(conn, "cwe", 100)
    _add_edges(conn, "supersedes", 150)
    _add_edges(conn, "nist", 20)


def test_clean_index_reports_no_failures(conn):
    _all_rels(conn)
    assert run_checks(conn, expected_requirements=3, check_edge_floors=False) == []


def test_detects_wrong_requirement_count(conn):
    _all_rels(conn)
    failures = run_checks(conn, expected_requirements=345, check_edge_floors=False)
    assert any("requirement count" in f for f in failures)


def test_detects_empty_chunks(conn):
    _all_rels(conn)
    sid = conn.execute("SELECT id FROM sections LIMIT 1").fetchone()[0]
    conn.execute("INSERT INTO chunks (section_id, text, token_est) VALUES (?, '   ', 0)", (sid,))
    conn.commit()
    assert any(
        "empty chunk" in f
        for f in run_checks(conn, expected_requirements=3, check_edge_floors=False)
    )


def test_detects_document_with_no_chunks(conn):
    _all_rels(conn)
    pid = conn.execute("SELECT id FROM packs WHERE name='cheatsheets'").fetchone()[0]
    conn.execute(
        "INSERT INTO docs (pack_id, doc_key, title) VALUES (?, 'Empty_Doc', 'Empty')", (pid,)
    )
    conn.commit()
    assert any(
        "Empty_Doc" in f for f in run_checks(conn, expected_requirements=3, check_edge_floors=False)
    )


def test_detects_dangling_guidance_link(conn):
    _all_rels(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('asvs_section', 'V6.2', 'doc', 'Does_Not_Exist_Cheat_Sheet',"
        " 'guidance', 'IndexASVS.md')"
    )
    conn.commit()
    assert any(
        "Does_Not_Exist_Cheat_Sheet" in f
        for f in run_checks(conn, expected_requirements=3, check_edge_floors=False)
    )


def test_detects_requirement_without_a_chunk(conn):
    _all_rels(conn)
    conn.execute("UPDATE requirements SET chunk_id = NULL WHERE req_id = 'V6.2.1'")
    conn.commit()
    assert any(
        "V6.2.1" in f for f in run_checks(conn, expected_requirements=3, check_edge_floors=False)
    )


def test_detects_unbalanced_code_fence(conn):
    _all_rels(conn)
    sid = conn.execute("SELECT id FROM sections LIMIT 1").fetchone()[0]
    conn.execute(
        "INSERT INTO chunks (section_id, text, token_est) VALUES (?, 'text ``` unclosed', 3)",
        (sid,),
    )
    conn.commit()
    assert any(
        "code fence" in f
        for f in run_checks(conn, expected_requirements=3, check_edge_floors=False)
    )


def test_a_missing_relationship_type_is_an_error(conn):
    """The CWE mapping once produced zero edges because it is keyed on
    bleeding-edge ids, and drop-and-count made that look like normal operation.
    owasp_related advertises all four relationships, so none may be empty."""
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    for rel in ("guidance", "cwe", "supersedes", "nist"):
        assert any(rel in f and "zero edges" in f for f in failures), rel


def test_all_four_relationship_types_present_clears_the_check(conn):
    _all_rels(conn)
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert not any("zero edges" in f for f in failures)
    assert not any("expected at least" in f for f in failures)


def test_a_collapsed_relationship_count_is_flagged(conn):
    """A rel type dropping from hundreds of edges to a handful means an upstream
    format change is being silently swallowed."""
    ingest_guidance_links(conn, "tests/fixtures/IndexASVS_sample.md")
    _add_edges(conn, "guidance", 100, source="test")
    _add_edges(conn, "cwe", 2)
    _add_edges(conn, "supersedes", 150)
    _add_edges(conn, "nist", 20)
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=True)
    assert any("only 2 'cwe' links" in f for f in failures)


def test_a_cwe_mapping_pointing_at_nothing_is_reported(conn):
    """Four ASVS-mapped ids turned out to be Categories rather than Weaknesses.
    A heuristic missed all four; only resolving every edge finds that."""
    _ingest_cwe_fixture(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source) "
        "VALUES ('requirement','V1.1.1','cwe','CWE-99999','cwe','test')"
    )
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert any("CWE-99999" in f for f in failures)


def test_a_cwe_mapping_that_resolves_is_not_reported(conn):
    _ingest_cwe_fixture(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source) "
        "VALUES ('requirement','V1.1.1','cwe','CWE-789','cwe','test')"
    )
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert not any("catalogue entry" in f for f in failures)


def test_a_dangling_intra_cwe_edge_is_not_reported(conn):
    """rel='cwe' is the ASVS-to-CWE mapping. cwe_child/cwe_peer/cwe_member are
    CWE's own graph, and those legitimately point outside any ingested subset --
    measured against tests/fixtures/cwec_sample.xml, all four of CWE-320's
    Has_Member targets are outside the fixture, all fifteen of CWE-255's, plus
    seven Related_Weakness edges from the kept weaknesses. Widening the check to
    rel LIKE 'cwe%' turns 26 correct rows (23 distinct ids) into a build failure.
    """
    _ingest_cwe_fixture(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source) "
        "VALUES ('cwe','CWE-789','cwe','CWE-99999','cwe_child','test')"
    )
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    # Both halves are needed. The report names only the first five ids, and
    # CWE-99999 sorts outside the five that a widened check surfaces, so the id
    # assertion on its own stays green while the check fires on all 24.
    assert not any("catalogue entry" in f for f in failures)
    assert not any("CWE-99999" in f for f in failures)


def test_the_check_is_skipped_when_the_catalogue_is_absent(conn):
    """A lite build without the CWE pack must not fail on a mapping it cannot
    resolve. The ASVS-to-CWE links exist there regardless of the pack."""
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source) "
        "VALUES ('requirement','V1.1.1','cwe','CWE-99999','cwe','test')"
    )
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert not any("catalogue entry" in f for f in failures)
    assert not any("CWE-99999" in f for f in failures)


def test_zero_cwe_child_edges_is_an_error_when_the_catalogue_is_present(conn):
    """A total collapse of Related_Weaknesses parsing produces no cwe_child rows
    while every entry still lands, so nothing else in this module notices."""
    _ingest_cwe_fixture(conn)
    conn.execute("DELETE FROM links WHERE rel = 'cwe_child'")
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert any("cwe_child" in f and "zero edges" in f for f in failures)


def test_the_cwe_graph_rels_are_present_in_the_fixture_catalogue(conn):
    _ingest_cwe_fixture(conn)
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    for rel in ("cwe_child", "cwe_peer", "cwe_member"):
        assert not any(rel in f and "zero edges" in f for f in failures), rel


def test_a_catalogue_less_index_is_not_asked_for_the_cwe_graph_rels(conn):
    """The three rels only exist when the CWE pack is ingested. Requiring them
    unconditionally would fail every build that omits the pack."""
    _all_rels(conn)
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    for rel in ("cwe_child", "cwe_peer", "cwe_member"):
        assert not any(rel in f for f in failures), rel


def test_detects_too_many_oversized_chunks(conn):
    _all_rels(conn)
    sid = conn.execute("SELECT id FROM sections LIMIT 1").fetchone()[0]
    for _ in range(50):
        conn.execute(
            "INSERT INTO chunks (section_id, text, token_est) VALUES (?, 'x', 9999)", (sid,)
        )
    conn.commit()
    failures = run_checks(conn, expected_requirements=3, check_edge_floors=False)
    assert any("truncated" in f or "token window" in f for f in failures)


def test_failures_are_human_readable_strings(conn):
    failures = run_checks(conn, expected_requirements=999, check_edge_floors=False)
    assert failures
    assert all(isinstance(f, str) and f.strip() for f in failures)
