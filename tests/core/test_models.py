import pytest

from owasp_kb.core.models import Chunk, OutlineNode, RelatedEdge, RequirementRow, SearchHit


def test_search_hit_citation_for_requirement():
    hit = SearchHit(
        pack="asvs",
        pack_version="5.0.0",
        req_id="V6.2.1",
        doc_key=None,
        anchor=None,
        heading_path="V6 > V6.2",
        text="Verify that...",
        score=1.0,
    )
    assert hit.citation == "ASVS 5.0.0 V6.2.1"


def test_search_hit_citation_for_corpus_section():
    hit = SearchHit(
        pack="cheatsheets",
        pack_version="20260724",
        req_id=None,
        doc_key="Authentication_Cheat_Sheet",
        anchor="password-storage",
        heading_path="Authentication > Password Storage",
        text="Use argon2id",
        score=0.5,
    )
    assert hit.citation == "Authentication_Cheat_Sheet#password-storage"


def test_search_hit_citation_for_whole_document():
    hit = SearchHit(
        pack="cheatsheets",
        pack_version="20260724",
        req_id=None,
        doc_key="Authentication_Cheat_Sheet",
        anchor=None,
        heading_path="Authentication",
        text="x",
        score=0.5,
    )
    assert hit.citation == "Authentication_Cheat_Sheet"


def test_hit_without_any_identifier_is_rejected():
    """A hit with neither identifier would render as the literal 'None', which
    looks like a citation and points nowhere."""
    with pytest.raises(ValueError, match="citable"):
        SearchHit(
            pack="cheatsheets",
            pack_version="20260724",
            req_id=None,
            doc_key=None,
            anchor=None,
            heading_path="x",
            text="y",
            score=0.0,
        )


def test_anchor_without_doc_key_is_rejected():
    """Would otherwise render as 'None#password-storage'."""
    with pytest.raises(ValueError, match="citable"):
        SearchHit(
            pack="cheatsheets",
            pack_version="20260724",
            req_id=None,
            doc_key=None,
            anchor="password-storage",
            heading_path="x",
            text="y",
            score=0.0,
        )


def test_citation_falls_back_to_the_raw_pack_name_for_an_unlabelled_pack():
    """Later packs (WSTG, MASVS) must cite sensibly before they get a label."""
    hit = SearchHit(
        pack="wstg",
        pack_version="4.2",
        req_id="WSTG-ATHN-01",
        doc_key=None,
        anchor=None,
        heading_path="x",
        text="y",
        score=0.0,
    )
    assert hit.citation == "wstg 4.2 WSTG-ATHN-01"


def test_chunk_and_row_types_construct():
    assert Chunk(anchor="a", heading_path="T > A", depth=2, ord=0, text="t", token_est=1).ord == 0
    assert OutlineNode(anchor="a", heading="A", depth=2, ord=0).heading == "A"
    assert RelatedEdge(rel="guidance", to_kind="doc", to_id="X", source="IndexASVS.md").rel
    row = RequirementRow(
        req_id="V6.2.1",
        chapter_id="V6",
        chapter_name="Authentication",
        section_id="V6.2",
        section_name="Password Security",
        text="t",
        level="2",
    )
    assert row.level == "2"


def test_a_masvs_control_cites_with_the_standard_name_and_version():
    hit = SearchHit(
        pack="masvs",
        pack_version="2.1.0",
        req_id="MASVS-STORAGE-1",
        doc_key=None,
        anchor=None,
        heading_path="Storage",
        text="t",
        score=0.0,
    )
    assert hit.citation == "MASVS 2.1.0 MASVS-STORAGE-1"


def test_a_requirement_row_may_carry_no_level():
    """MASVS 2.x has no levels; the row type must say so rather than forcing a
    sentinel that a numeric filter would then treat as level 0."""
    row = RequirementRow(
        req_id="MASVS-STORAGE-1",
        chapter_id="MASVS-STORAGE",
        chapter_name="Storage",
        section_id="MASVS-STORAGE",
        section_name="Storage",
        text="The app securely stores sensitive data.",
        level=None,
    )
    assert row.level is None
