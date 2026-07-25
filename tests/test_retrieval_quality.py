"""Retrieval quality gate against the real, fully-built indexes.

Skipped unless the indexes exist, so unit runs stay fast. Run after
'make index' and 'make index-full'.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from owasp_kb.core.db import connect, is_wal_index
from owasp_kb.core.kb import Kb

FULL_INDEX = Path(os.environ.get("OWASP_KB_FULL_INDEX", "dist/owasp-kb-full.sqlite"))
LITE_INDEX = Path(os.environ.get("OWASP_KB_LITE_INDEX", "dist/owasp-kb-lite.sqlite"))

TOP_N = 3

PARAPHRASED_QUERIES = [
    ("stop people brute-forcing logins", "Authentication_Cheat_Sheet"),
    ("keep my users logged out after they close the tab", "Session_Management_Cheat_Sheet"),
    ("someone is uploading a php shell disguised as a jpeg", "File_Upload_Cheat_Sheet"),
    ("how do I store passwords", "Password_Storage_Cheat_Sheet"),
]

NOISE_QUERIES = ["zzzznotpresentanywhere", "qwertyuiop asdfghjkl", "the of and is a"]


def _kb(path: Path, *, load_vec: bool) -> Kb:
    if not path.exists():
        pytest.skip(f"no index at {path}; run 'make index-full' first")
    return Kb(connect(path, load_vec=load_vec, read_only=True))


@pytest.fixture(scope="module")
def full():
    return _kb(FULL_INDEX, load_vec=True)


@pytest.fixture(scope="module")
def lite():
    return _kb(LITE_INDEX, load_vec=False)


def _doc_rank(kb: Kb, query: str, expected: str, limit: int = 20) -> int | None:
    try:
        hits = kb.search(query, pack="cheatsheets", limit=limit)
    except LookupError:
        return None
    seen: list[str] = []
    for hit in hits:
        if hit.doc_key not in seen:
            seen.append(hit.doc_key)
    return seen.index(expected) + 1 if expected in seen else None


# -- content ----------------------------------------------------------


def test_full_index_has_the_expected_content(full):
    info = full.info()
    assert {p.name for p in info.packs} == {"asvs", "cheatsheets"}
    assert next(p.version for p in info.packs if p.name == "asvs") == "5.0.0"
    assert len(full.checklist("asvs")) == 345


def test_level_filters_return_the_measured_counts(full):
    assert len(full.checklist("asvs", level="1")) == 70
    assert len(full.checklist("asvs", level="2")) == 183
    assert len(full.checklist("asvs", level="3")) == 92


def test_full_index_uses_hybrid_retrieval(full):
    assert full.info().retrieval_mode == "hybrid"


def test_lite_index_uses_lexical_retrieval(lite):
    assert lite.info().retrieval_mode == "lexical"


def test_both_indexes_are_finalized_for_readonly_serving():
    """A WAL index cannot be opened from the image's non-writable directory."""
    for path in (LITE_INDEX, FULL_INDEX):
        if path.exists():
            assert not is_wal_index(path), f"{path} would fail to serve from the image"


# -- relationships ----------------------------------------------------


def test_requirement_lookup_reaches_its_guidance(full):
    """The highest-value query in the system: what explains this requirement."""
    edges = full.related("V6.2.1", rel="guidance")
    assert any("Authentication" in e.to_id for e in edges)


def test_all_four_relationship_types_are_reachable(full):
    rels = {e.rel for e in full.related("V6.2.1")}
    assert rels == {"guidance", "cwe", "supersedes", "nist"}


# -- retrieval quality ------------------------------------------------


@pytest.mark.parametrize("query,expected_doc", PARAPHRASED_QUERIES)
def test_hybrid_ranks_paraphrased_queries_within_the_top_five(full, query, expected_doc):
    """Rank, not mere presence.

    BM25 alone already returns three of these inside the top 8, at about rank 3,
    so asserting "somewhere in the top 8" would pass for lexical-only and hide
    the difference the embedder buys. Five rather than three because hybrid
    measured at rank 4 on the brute-forcing query: RRF blends, so when its inputs
    disagree it lands between them.
    """
    rank = _doc_rank(full, query, expected_doc)
    assert rank is not None and rank <= 5, f"{expected_doc} ranked {rank} for {query!r}"


def test_hybrid_mean_rank_beats_lexical(full, lite):
    """The figure that justifies the full variant. Measured: 3.4 lexical, 2.0
    hybrid. A per-query 'hybrid beats both' assertion would be wrong -- fusion
    lands between its inputs when they disagree."""

    def mean_rank(kb):
        ranks = [_doc_rank(kb, q, d) or 20 for q, d in PARAPHRASED_QUERIES]
        return sum(ranks) / len(ranks)

    assert mean_rank(full) < mean_rank(lite)


# -- relevance floors -------------------------------------------------


@pytest.mark.parametrize("query", NOISE_QUERIES)
def test_noise_queries_report_no_match_rather_than_inventing_relevance(full, query):
    """Vector search always has a nearest neighbour and BM25 matched stopwords,
    so an off-topic question used to return confident security guidance."""
    with pytest.raises(LookupError):
        full.search(query, limit=5)


def test_no_match_message_distinguishes_itself_from_no_requirements(full):
    with pytest.raises(LookupError) as excinfo:
        full.search("zzzznotpresentanywhere", limit=5)
    assert "not that no security requirements apply" in str(excinfo.value).lower()


# -- informational ----------------------------------------------------


def test_report_lite_versus_full_rank(full, lite, capsys):
    """Never fails. Reports rank so a regression in the embedder's value is
    visible rather than inferred."""
    rows = [(q, _doc_rank(lite, q, d), _doc_rank(full, q, d)) for q, d in PARAPHRASED_QUERIES]
    with capsys.disabled():
        print("\n  rank of expected document (1 = best, None = absent from top 20)")
        for query, lite_rank, full_rank in rows:
            print(f"    lite={str(lite_rank):>5}  full={str(full_rank):>5}  {query}")
        lite_mean = sum(r[1] or 20 for r in rows) / len(rows)
        full_mean = sum(r[2] or 20 for r in rows) / len(rows)
        print(f"    mean rank: lite {lite_mean:.1f}  full {full_mean:.1f}")
        if full_mean >= lite_mean:
            print("    NOTE: full does not improve mean rank - reconsider the embedder.")
