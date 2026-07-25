import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.retrieval.lexical import LexicalRetriever, to_fts_query
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets


@pytest.fixture
def retriever(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    ingest_asvs(c, "tests/fixtures/asvs_sample.flat.json",
                version="5.0.0", license="CC-BY-SA-4.0")
    ingest_cheatsheets(c, "tests/fixtures/cheatsheets", version="20260724",
                       commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
                       license="CC-BY-SA-4.0")
    return LexicalRetriever(c)


def test_mode_is_lexical(retriever):
    assert retriever.mode == "lexical"


def test_finds_matching_content(retriever):
    hits = retriever.search("password", limit=10)
    assert hits
    assert any("password" in h.text.lower() for h in hits)


def test_results_are_ordered_best_first(retriever):
    """Higher score must mean better. SQLite bm25() is negative-better, and that
    convention must not leak out — a later task fuses these with vector scores."""
    hits = retriever.search("passwords", limit=10)
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)


def test_pack_filter_restricts_results(retriever):
    hits = retriever.search("password", pack="cheatsheets", limit=10)
    assert hits
    assert {h.pack for h in hits} == {"cheatsheets"}


def test_level_filter_applies_to_requirements(retriever):
    hits = retriever.search("password", pack="asvs", level="1", limit=10)
    assert hits
    assert all(h.req_id == "V6.2.1" for h in hits)


def test_requirement_hits_carry_citable_ids(retriever):
    hits = retriever.search("canonical form", pack="asvs", limit=5)
    assert hits[0].req_id == "V1.1.1"
    assert hits[0].citation == "ASVS 5.0.0 V1.1.1"


def test_corpus_hits_carry_doc_key_and_anchor(retriever):
    hits = retriever.search("argon2id", pack="cheatsheets", limit=5)
    assert hits[0].doc_key == "Authentication_Cheat_Sheet"
    assert hits[0].anchor == "password-storage"
    assert hits[0].citation == "Authentication_Cheat_Sheet#password-storage"


def test_every_hit_is_citable(retriever):
    """SearchHit rejects an uncitable hit at construction, so a bad join would
    raise rather than yield a hit citing 'None'."""
    for hit in retriever.search("the", limit=20):
        assert hit.citation
        assert "None" not in hit.citation


def test_hits_carry_the_pack_version(retriever):
    hits = retriever.search("argon2id", pack="cheatsheets", limit=1)
    assert hits[0].pack_version == "20260724"


def test_limit_is_honoured(retriever):
    assert len(retriever.search("the", limit=2)) <= 2


def test_no_match_returns_empty_list(retriever):
    assert retriever.search("zzzznotpresent", limit=5) == []


def test_unknown_pack_raises_naming_available_packs(retriever):
    with pytest.raises(KeyError) as excinfo:
        retriever.search("password", pack="nope", limit=5)
    assert "asvs" in str(excinfo.value)


@pytest.mark.parametrize("hostile", [
    'password OR "session (management"',
    "unbalanced \" quote",
    "star* and NEAR(a b)",
    "-leading-hyphen",
    "",
    "   ",
    "^caret AND (unclosed",
    "colon:prefix",
])
def test_hostile_query_syntax_never_raises(retriever, hostile):
    """Queries arrive from an agent relaying a user's words; raw FTS5 syntax in
    them must not produce an OperationalError."""
    retriever.search(hostile, limit=5)


def test_to_fts_query_quotes_every_term():
    assert to_fts_query("password storage") == '"password" OR "storage"'


def test_to_fts_query_strips_operators():
    assert "OR" in to_fts_query("a OR b")  # the joiner, not the user's operator
    assert to_fts_query("NEAR(x y)") == '"NEAR" OR "x" OR "y"'


def test_to_fts_query_on_empty_input_is_safe():
    assert to_fts_query("") == '""'
    assert to_fts_query("!!!") == '""'
