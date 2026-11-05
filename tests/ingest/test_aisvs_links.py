from pathlib import Path

import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest import aisvs_guidance
from owasp_kb.ingest.links import AISVS_REFERENCES, CS_TO_AISVS, ingest_aisvs_guidance_links
from owasp_kb.ingest.packs.aisvs import ingest_aisvs, load_chapters

FIXTURE_DIR = Path("tests/fixtures/aisvs")
REAL_DIR = Path("data/aisvs")

# The shape of the RAG Security cheat sheet's own link to AISVS C08 at the pinned
# Cheat Sheet Series commit: a blob URL on a branch, into 1.0/en/.
RAG_REFERENCE = (
    "- [OWASP AISVS C08: Memory, Embeddings and Vector Database Security]"
    "(https://github.com/OWASP/AISVS/blob/main/1.0/en/"
    "0x10-C08-Memory-Embeddings-and-Vector-Database.md)\n"
)


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    ingest_aisvs(c, FIXTURE_DIR, version="1.01", license="CC-BY-SA-4.0")
    return c


@pytest.fixture
def cheatsheets(tmp_path):
    directory = tmp_path / "cheatsheets"
    directory.mkdir()
    (directory / "RAG_Security_Cheat_Sheet.md").write_text(
        "# RAG Security Cheat Sheet\n\n## References\n\n" + RAG_REFERENCE, encoding="utf-8"
    )
    (directory / "Authentication_Cheat_Sheet.md").write_text("# Auth\n", encoding="utf-8")
    return directory


@pytest.fixture
def two_chapter_map(monkeypatch):
    """The fixture holds only C2 and C10, so the real map would name absent chapters."""
    monkeypatch.setattr(
        "owasp_kb.ingest.links.CURATED_GUIDANCE",
        {"AI_Agent_Security_Cheat_Sheet": ("C2",), "Secure_Coding_with_AI_Cheat_Sheet": ("C10",)},
    )


def _edges(conn, source=None):
    sql = "SELECT from_kind, from_id, to_id, source FROM links WHERE rel = 'guidance'"
    params = ()
    if source is not None:
        sql += " AND source = ?"
        params = (source,)
    return {(r[0], r[1], r[2], r[3]) for r in conn.execute(sql, params)}


def test_chapter_references_become_guidance_edges(conn, cheatsheets, two_chapter_map):
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert {(e[1], e[2]) for e in _edges(conn, AISVS_REFERENCES)} == {
        ("C2", "LLM_Prompt_Injection_Prevention_Cheat_Sheet"),
        ("C10", "MCP_Security_Cheat_Sheet"),
    }


def test_edges_are_keyed_on_aisvs_section(conn, cheatsheets, two_chapter_map):
    """The kind is per pack: asvs_section edges come from IndexASVS.md only."""
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert {e[0] for e in _edges(conn)} == {"aisvs_section"}


def test_a_non_cheat_sheet_reference_is_not_an_edge(conn, cheatsheets, two_chapter_map):
    """C2's References also link the LLM Top 10, which is not a document here."""
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert all(e[2].endswith("_Cheat_Sheet") for e in _edges(conn))


def test_a_cheat_sheet_link_to_an_unknown_chapter_is_dropped(conn, cheatsheets, two_chapter_map):
    """The RAG sheet links C8, which the two-chapter fixture does not hold. An
    edge from an id no requirement carries would resolve to nothing."""
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert not _edges(conn, CS_TO_AISVS)


def test_a_cheat_sheet_link_to_a_known_chapter_is_kept(conn, tmp_path, two_chapter_map):
    directory = tmp_path / "cs"
    directory.mkdir()
    (directory / "MCP_Security_Cheat_Sheet.md").write_text(
        "[C10](https://github.com/OWASP/AISVS/blob/v1.01/1.01/en/0x10-C10-MCP-Security.md)\n",
        encoding="utf-8",
    )
    (directory / "RAG_Security_Cheat_Sheet.md").write_text(
        "[C2](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C02-Input-Validation.md)\n",
        encoding="utf-8",
    )
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, directory)
    assert {(e[1], e[2]) for e in _edges(conn, CS_TO_AISVS)} == {
        ("C2", "RAG_Security_Cheat_Sheet")
    }, "the C10 -> MCP edge is upstream's own reference, so that source keeps it"


def test_curated_edges_carry_their_own_source(conn, cheatsheets, two_chapter_map):
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert {(e[1], e[2]) for e in _edges(conn, aisvs_guidance.CURATED_SOURCE)} == {
        ("C2", "AI_Agent_Security_Cheat_Sheet"),
        ("C10", "Secure_Coding_with_AI_Cheat_Sheet"),
    }


def test_upstream_wins_over_a_curated_duplicate(conn, cheatsheets, monkeypatch):
    monkeypatch.setattr(
        "owasp_kb.ingest.links.CURATED_GUIDANCE",
        {"MCP_Security_Cheat_Sheet": ("C10",)},
    )
    ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    rows = [e for e in _edges(conn) if e[2] == "MCP_Security_Cheat_Sheet"]
    assert [r[3] for r in rows] == [AISVS_REFERENCES]


def test_a_curated_chapter_the_release_lacks_stops_the_build(conn, cheatsheets, monkeypatch):
    monkeypatch.setattr(
        "owasp_kb.ingest.links.CURATED_GUIDANCE", {"AI_Agent_Security_Cheat_Sheet": ("C99",)}
    )
    with pytest.raises(ValueError, match="C99"):
        ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)


def test_re_ingest_adds_nothing(conn, cheatsheets, two_chapter_map):
    first = ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets)
    assert first == 4
    assert ingest_aisvs_guidance_links(conn, FIXTURE_DIR, cheatsheets) == 0


def test_the_curated_map_names_only_cheat_sheet_doc_keys():
    for doc_key, chapters in aisvs_guidance.CURATED_GUIDANCE.items():
        assert doc_key.endswith("_Cheat_Sheet"), doc_key
        assert chapters, f"{doc_key} maps to no chapter"


@pytest.mark.realdata
def test_the_curated_map_names_only_real_aisvs_chapters():
    if not REAL_DIR.exists():
        pytest.skip(f"no AISVS chapters at {REAL_DIR}; run the fetch step first")
    real = {c.chapter_id for c in load_chapters(REAL_DIR)}
    named = {c for chapters in aisvs_guidance.CURATED_GUIDANCE.values() for c in chapters}
    assert named <= real, named - real
