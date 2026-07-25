from owasp_kb.core.models import Chunk, OutlineNode, RelatedEdge, RequirementRow, SearchHit


def test_search_hit_citation_for_requirement():
    hit = SearchHit(
        pack="asvs", pack_version="5.0.0", req_id="V6.2.1", doc_key=None,
        anchor=None, heading_path="V6 > V6.2", text="Verify that...", score=1.0,
    )
    assert hit.citation == "ASVS 5.0.0 V6.2.1"


def test_search_hit_citation_for_corpus_section():
    hit = SearchHit(
        pack="cheatsheets", pack_version="20260724", req_id=None,
        doc_key="Authentication_Cheat_Sheet", anchor="password-storage",
        heading_path="Authentication > Password Storage", text="Use argon2id", score=0.5,
    )
    assert hit.citation == "Authentication_Cheat_Sheet#password-storage"


def test_search_hit_citation_for_whole_document():
    hit = SearchHit(
        pack="cheatsheets", pack_version="20260724", req_id=None,
        doc_key="Authentication_Cheat_Sheet", anchor=None,
        heading_path="Authentication", text="x", score=0.5,
    )
    assert hit.citation == "Authentication_Cheat_Sheet"


def test_chunk_and_row_types_construct():
    assert Chunk(anchor="a", heading_path="T > A", depth=2, ord=0, text="t", token_est=1).ord == 0
    assert OutlineNode(anchor="a", heading="A", depth=2, ord=0).heading == "A"
    assert RelatedEdge(rel="guidance", to_kind="doc", to_id="X", source="IndexASVS.md").rel
    row = RequirementRow(
        req_id="V6.2.1", chapter_id="V6", chapter_name="Authentication",
        section_id="V6.2", section_name="Password Security", text="t", level="2",
    )
    assert row.level == "2"
