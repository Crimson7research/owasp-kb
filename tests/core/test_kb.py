import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.kb import Kb
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import ingest_cwe_links, ingest_guidance_links
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets


@pytest.fixture
def kb(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    ingest_asvs(
        conn, "tests/fixtures/asvs_sample.flat.json", version="5.0.0", license="CC-BY-SA-4.0"
    )
    ingest_cheatsheets(
        conn,
        "tests/fixtures/cheatsheets",
        version="20260724",
        commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
        license="CC-BY-SA-4.0",
    )
    ingest_guidance_links(conn, "tests/fixtures/IndexASVS_sample.md")
    ingest_cwe_links(
        conn,
        "tests/fixtures/cwe_mapping_sample.json",
        be_to_release_path="tests/fixtures/mapping_be_to_500_sample.yml",
    )
    return Kb(conn)


# -- info -------------------------------------------------------------


def test_info_reports_packs_and_mode(kb):
    info = kb.info()
    assert info.retrieval_mode == "lexical"
    assert {p.name for p in info.packs} == {"asvs", "cheatsheets"}


def test_info_exposes_versions_for_citation(kb):
    versions = {p.name: p.version for p in kb.info().packs}
    assert versions["asvs"] == "5.0.0"
    assert versions["cheatsheets"] == "20260724"


# -- search -----------------------------------------------------------


def test_search_returns_hits_with_citations(kb):
    hits = kb.search("password", limit=5)
    assert hits
    assert all(h.citation for h in hits)


def test_search_with_no_match_raises_lookup_error_naming_packs(kb):
    """An agent reads [] as 'no requirements apply', which is a different and
    dangerous claim from 'nothing matched'."""
    with pytest.raises(LookupError) as excinfo:
        kb.search("zzzznotpresent", limit=5)
    message = str(excinfo.value)
    assert "no match" in message.lower()
    assert "asvs" in message and "cheatsheets" in message
    assert "not that no security requirements apply" in message.lower()


def test_search_no_match_within_a_pack_names_only_that_pack(kb):
    with pytest.raises(LookupError) as excinfo:
        kb.search("zzzznotpresent", pack="asvs", limit=5)
    assert "asvs" in str(excinfo.value)


def test_search_unknown_pack_raises_key_error(kb):
    with pytest.raises(KeyError):
        kb.search("password", pack="nope", limit=5)


# -- outline / get ----------------------------------------------------


def test_outline_lists_sections_in_order(kb):
    nodes = kb.outline("Authentication_Cheat_Sheet")
    assert [n.anchor for n in nodes] == [n.anchor for n in sorted(nodes, key=lambda n: n.ord)]
    assert "password-storage" in {n.anchor for n in nodes}


def test_outline_heading_is_the_leaf_not_the_full_path(kb):
    nodes = {n.anchor: n for n in kb.outline("Authentication_Cheat_Sheet")}
    assert nodes["password-storage"].heading == "Password Storage"


def test_outline_unknown_doc_raises_with_suggestions(kb):
    with pytest.raises(KeyError) as excinfo:
        kb.outline("Authentication_Cheatsheet")
    assert "Authentication_Cheat_Sheet" in str(excinfo.value)


def test_get_whole_document(kb):
    text = kb.get("Authentication_Cheat_Sheet")
    assert "argon2id" in text
    assert "credential stuffing" in text


def test_get_single_section_is_smaller_than_whole_document(kb):
    section = kb.get("Authentication_Cheat_Sheet", anchor="password-storage")
    whole = kb.get("Authentication_Cheat_Sheet")
    assert "argon2id" in section
    assert len(section) < len(whole)


def test_get_unknown_anchor_lists_the_available_ones(kb):
    with pytest.raises(KeyError) as excinfo:
        kb.get("Authentication_Cheat_Sheet", anchor="nope")
    assert "password-storage" in str(excinfo.value)


def test_get_unknown_doc_raises_with_suggestions(kb):
    with pytest.raises(KeyError) as excinfo:
        kb.get("Authentication_Cheatsheet")
    assert "Authentication_Cheat_Sheet" in str(excinfo.value)


# -- checklist --------------------------------------------------------


def test_checklist_filters_by_chapter(kb):
    assert {r.req_id for r in kb.checklist("asvs", chapter="V6")} == {"V6.2.1", "V6.2.2"}


def test_checklist_level_is_cumulative(kb):
    """An ASVS L2 assessment verifies L1 and L2 requirements. Exact-match would
    return only the L2-tagged ones and omit password minimums from a report
    labelled L2."""
    assert {r.req_id for r in kb.checklist("asvs", level="1")} == {"V6.2.1"}
    assert {r.req_id for r in kb.checklist("asvs", level="2")} == {"V1.1.1", "V6.2.1", "V6.2.2"}


def test_checklist_level_exact_returns_only_that_tier(kb):
    assert {r.req_id for r in kb.checklist("asvs", level_exact="2")} == {"V1.1.1", "V6.2.2"}
    assert {r.req_id for r in kb.checklist("asvs", level_exact="1")} == {"V6.2.1"}


def test_checklist_rejects_both_level_arguments(kb):
    with pytest.raises(ValueError, match="level_exact"):
        kb.checklist("asvs", level="2", level_exact="2")


def test_checklist_level_composes_with_chapter(kb):
    assert {r.req_id for r in kb.checklist("asvs", chapter="V6", level="2")} == {"V6.2.1", "V6.2.2"}


def test_checklist_filters_by_section_and_req_id(kb):
    assert len(kb.checklist("asvs", section="V6.2")) == 2
    assert [r.req_id for r in kb.checklist("asvs", req_id="V6.2.2")] == ["V6.2.2"]


def test_checklist_is_deterministically_ordered(kb):
    assert [r.req_id for r in kb.checklist("asvs")] == ["V1.1.1", "V6.2.1", "V6.2.2"]


def test_checklist_orders_numerically_not_lexically(kb, tmp_path):
    """V10 must sort after V9. String ordering silently corrupts a gap report."""
    import json

    from owasp_kb.core.db import connect as _connect
    from owasp_kb.core.schema import create_schema as _create

    reqs = []
    for chapter in (2, 9, 10):
        reqs.append(
            {
                "chapter_id": f"V{chapter}",
                "chapter_name": f"C{chapter}",
                "section_id": f"V{chapter}.1",
                "section_name": "S",
                "req_id": f"V{chapter}.1.1",
                "req_description": "text",
                "L": "1",
            }
        )
    path = tmp_path / "ord.json"
    path.write_text(json.dumps({"requirements": reqs}))
    conn = _connect(tmp_path / "ord.sqlite")
    _create(conn)
    ingest_asvs(conn, path, version="5.0.0", license="CC-BY-SA-4.0")
    assert [r.req_id for r in Kb(conn).checklist("asvs")] == ["V2.1.1", "V9.1.1", "V10.1.1"]


def test_checklist_on_corpus_pack_raises_naming_the_alternative(kb):
    with pytest.raises(ValueError) as excinfo:
        kb.checklist("cheatsheets")
    message = str(excinfo.value)
    assert "corpus" in message
    assert "owasp_search" in message or "owasp_outline" in message


def test_checklist_unknown_pack_raises(kb):
    with pytest.raises(KeyError):
        kb.checklist("nope")


def test_checklist_returns_the_bare_requirement_text(kb):
    """requirements.text holds the clean description; the chapter/section prefix
    belongs only in the chunk used for search."""
    row = [r for r in kb.checklist("asvs", req_id="V6.2.1")][0]
    assert row.text.startswith("Verify")
    assert "Authentication >" not in row.text


# -- related ----------------------------------------------------------


def test_related_resolves_requirement_to_cwe(kb):
    assert any(e.rel == "cwe" and e.to_id == "CWE-521" for e in kb.related("V6.2.1"))


def test_related_resolves_section_to_guidance(kb):
    assert any(e.to_id == "Authentication_Cheat_Sheet" for e in kb.related("V6.2"))


def test_related_rolls_a_requirement_up_to_its_section_guidance(kb):
    """IndexASVS.md maps sections, agents ask about requirements. Without
    roll-up the highest-value query in the system returns nothing."""
    edges = kb.related("V6.2.1")
    assert any(e.rel == "guidance" and e.to_id == "Authentication_Cheat_Sheet" for e in edges)


def test_related_filters_by_rel(kb):
    assert {e.rel for e in kb.related("V6.2.1", rel="cwe")} == {"cwe"}


def test_related_accepts_a_doc_key(kb):
    assert isinstance(kb.related("Authentication_Cheat_Sheet"), list)


def test_related_unknown_id_returns_empty_list(kb):
    """Unlike search, absence of edges is a real answer, not a failed lookup."""
    assert kb.related("V99.9.9") == []


def test_related_is_deterministically_ordered(kb):
    edges = kb.related("V6.2.1")
    assert edges == sorted(edges, key=lambda e: (e.rel, e.to_id))
