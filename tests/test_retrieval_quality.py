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
from owasp_kb.ingest.build import EXPECTED_REQUIREMENTS
from owasp_kb.ingest.lock import load_lock

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

SECURE_CODING_SKILL = Path("plugins/owasp-kb/skills/owasp-secure-coding/SKILL.md")

# Step 4 of the secure-coding process quotes these against pack="asvs", with the
# requirement each is measured to return first. Held verbatim: every case below also
# asserts the skill still quotes the string, so a reworded step fails here rather than
# leaving the file measuring a query nobody is taught any more.
ASVS_QUERIES_THE_SKILL_QUOTES = [
    ("SSRF allowlist input validation domain name IP address URL", "V1.3.6"),
    ("SSRF allowlist validate outbound request destination", "V1.3.6"),
    (
        "SSRF allowlist of identified and trusted applications the server may call, "
        "network layer firewall allowed routes",
        "V13.2.4",
    ),
]

# The step 2 probe, which the skill states must *not* be reused for the ASVS search.
DATA_FLOW_SENTENCE = "url supplied by an operator, used to make a request from the server"


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


def _req_rank(kb: Kb, query: str, expected: str, limit: int = 20) -> int | None:
    try:
        hits = kb.search(query, pack="asvs", limit=limit)
    except LookupError:
        return None
    ids = [hit.req_id for hit in hits]
    return ids.index(expected) + 1 if expected in ids else None


def _skill_quotes(query: str) -> bool:
    return query in " ".join(SECURE_CODING_SKILL.read_text().split())


def _skip_unless_hybrid(kb: Kb) -> None:
    """The skill's numbers were measured on the shipped hybrid retriever.

    An index without the ONNX model beside it degrades to lexical, and the ranks change
    completely: measured, the data-flow sentence returns 2 hits under hybrid and V1.3.6 at
    rank 24 of 50 under lexical. Asserting the hybrid figures against a lexical run reports
    a defect in the skill that is really a missing model, so skip -- and
    ``test_full_index_uses_hybrid_retrieval`` is the test that fails on the degradation.
    """
    if kb.info().retrieval_mode != "hybrid":
        pytest.skip("retrieval degraded to lexical; run scripts/download_model.py")


# -- content ----------------------------------------------------------


def test_full_index_has_the_expected_content(full):
    """Every pack the lock declares is in the built index, and every checklist
    pack holds the number of requirements the build gate expects.

    Both sides derived rather than listed. This assertion was
    ``== {"asvs", "cheatsheets", "cwe"}`` and would have failed the first CI
    build after a fourth pack was pinned -- in ci.yml and release.yml both,
    against a real index, on a billed runner. The lock is what decides which
    packs ship, so it is what this compares against.
    """
    info = full.info()
    assert {p.name for p in info.packs} == set(load_lock("sources.lock.yml").packs)
    assert next(p.version for p in info.packs if p.name == "asvs") == "5.0.0"
    for pack, expected in sorted(EXPECTED_REQUIREMENTS.items()):
        assert len(full.checklist(pack)) == expected, (
            f"{pack} holds a different requirement count than build.EXPECTED_REQUIREMENTS "
            "declares; the build gate and this index disagree"
        )


@pytest.mark.parametrize("index", ["full", "lite"])
def test_both_indexes_carry_the_cwe_catalogue(index, request):
    """Against the built index, not a fixture.

    The pack's own tests all ingest it by hand, so every one of them passed while
    build.py imported nothing from packs/cwe.py and catalogue_entries was empty in
    both shipped indexes. Lite is asserted too: it differs from full only by
    --with-vectors, so it gets the catalogue as well, and a claim that the pack is
    full-only would be false.
    """
    kb = request.getfixturevalue(index)
    packs = {p.name: p for p in kb.info().packs}
    assert packs["cwe"].type == "catalogue"
    assert packs["cwe"].version == "4.20"
    assert "CWE" in packs["cwe"].license, f"license is {packs['cwe'].license!r}"
    # CWE-320 is an Obsolete Category, and eight ASVS requirements cite it. If the
    # ingest ever narrowed to current Weaknesses, those citations would stop
    # resolving; this is the entry that says so first.
    assert kb.catalogue_entry("CWE-320").kind == "category"


def test_level_filters_are_cumulative_as_asvs_defines_them(full):
    """Levels are cumulative. An L2 assessment covers 253 requirements, not the
    183 tagged L2 -- returning 183 would silently drop every L1 requirement from
    a report labelled L2."""
    assert len(full.checklist("asvs", level="1")) == 70
    assert len(full.checklist("asvs", level="2")) == 253
    assert len(full.checklist("asvs", level="3")) == 345


def test_level_exact_returns_the_tagged_tier_only(full):
    assert len(full.checklist("asvs", level_exact="1")) == 70
    assert len(full.checklist("asvs", level_exact="2")) == 183
    assert len(full.checklist("asvs", level_exact="3")) == 92


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


# -- the queries the skills teach -------------------------------------


@pytest.mark.parametrize("query,expected", ASVS_QUERIES_THE_SKILL_QUOTES)
def test_the_asvs_queries_the_skill_quotes_rank_their_requirement_first(full, query, expected):
    """Nothing measured a query the skill teaches, which is how the defect shipped: step 4
    told an agent to search pack="asvs" with the step 2 data-flow sentence, that sentence
    never reaches V1.3.6, and the whole suite stayed green because every assertion was about
    the prose rather than about what the prose retrieves."""
    assert _skill_quotes(query), (
        f"the skill no longer quotes {query!r}; re-measure the query it quotes now rather "
        "than leaving this file asserting about a query nobody is taught"
    )
    _skip_unless_hybrid(full)
    rank = _req_rank(full, query, expected)
    assert rank == 1, f"{expected} ranked {rank} for {query!r} against pack='asvs'"


def test_the_data_flow_sentence_does_not_reach_the_ssrf_requirement(full):
    """The assertion that would have caught the original defect. The data-flow sentence is
    the right probe for the cheat sheets and the wrong one for ASVS -- measured, it returns
    exactly two unrelated requirements -- so the skill inverts the phrasing rule at step 4.
    Asserted as absence at a depth well past the default window, because the failure mode
    was a plausible-looking non-empty result, not an empty one."""
    assert _skill_quotes(DATA_FLOW_SENTENCE), (
        "the skill no longer quotes the data-flow sentence this case is the counter-example to"
    )
    _skip_unless_hybrid(full)
    rank = _req_rank(full, DATA_FLOW_SENTENCE, "V1.3.6", limit=50)
    assert rank is None, (
        f"V1.3.6 now ranks {rank} for the data-flow sentence; the skill tells agents this "
        "query cannot reach it, so either the corpus changed or the instruction is wrong"
    )


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


def test_every_flagged_vulnerability_is_served_by_the_corpus(full):
    """The regression test for the original defect: SSRF was absent from every
    trigger list while the corpus carried a dedicated cheat sheet and ASVS V1.3.6,
    and nothing compared the two. A name the hook flags and the corpus cannot answer
    sends an agent to a tool that returns nothing, which is worse than not sending
    it at all.

    Against the built index rather than the container over MCP stdio. Prototyping it
    the stdio way produced six false negatives -- LDAP injection, path traversal,
    deserialization, open redirect, server-side template injection and privilege
    escalation all reporting zero hits -- because thirteen requests were written and
    stdin was then closed, so the reader hit EOF and cancelled the work in flight.
    That is the race scripts/docker_smoke.sh documents and solved with a hold-open
    loop. Checked individually afterwards, every one of the six is well covered.
    """
    import sys

    path = str(Path("plugins/owasp-kb/bin").resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    from owasp_kb_cli.security_terms import VULNERABILITY_NAMES

    empty = [name for name in VULNERABILITY_NAMES if not full.search(name, limit=3)]
    assert not empty, (
        f"the hook flags {empty} and the corpus returns nothing for them; either "
        "drop the name or establish that the content is there"
    )
