from pathlib import Path

import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.kb import MAX_ANCESTOR_DEPTH, Kb
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import (
    ingest_cwe_links,
    ingest_guidance_links,
    ingest_nist_links,
    ingest_supersedes_links,
)
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.ingest.packs.cwe import ingest_cwe


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
    ingest_supersedes_links(conn, "tests/fixtures/mapping_v5_to_v4_sample.yml")
    ingest_nist_links(conn, "tests/fixtures/nist_sample.md")
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


def test_info_reports_link_coverage(kb):
    coverage = {c.rel: c for c in kb.info().link_coverage}
    assert "guidance" in coverage
    assert coverage["guidance"].total_requirements == 3


def test_coverage_counts_requirements_reachable_through_roll_up(kb):
    """guidance edges are keyed on section ids, so counting distinct from_id
    would undercount the requirements that can actually reach one."""
    coverage = {c.rel: c for c in kb.info().link_coverage}
    # the fixture maps section V6.2 to cheat sheets; both V6.2.x requirements reach it
    assert coverage["guidance"].requirements == 2


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


def test_checklist_returns_asvs_in_numeric_id_order(kb):
    """Pins the order the id-parsing ORDER BY used to produce, so moving it into
    a column cannot silently reshuffle a gap report."""
    rows = kb.checklist("asvs")
    assert [r.req_id for r in rows] == ["V1.1.1", "V6.2.1", "V6.2.2"]


def test_checklist_ordering_pins_the_component_order_not_just_numeric_parsing(kb, tmp_path):
    """The two neighbouring ordering tests pass under a permuted _sort_key: this was
    found by mutation-checking ef7efee and is the gap this test closes.

    test_checklist_returns_asvs_in_numeric_id_order uses V1.1.1, V6.2.1, V6.2.2 --
    V1.1.1 is componentwise <= both others regardless of which component is
    compared first, and the remaining two differ only in their last component, so
    every permutation of (chapter, section, number) sorts them the same way.
    test_checklist_orders_numerically_not_lexically holds section and number fixed
    at 1 and only varies chapter, so it likewise cannot tell one permutation from
    another. Both tests do prove _sort_key is exercised -- negating all three
    components fails them -- but not that the component *order* is pinned.

    V2.2.2, V2.10.1 and V10.2.1 can tell every wrong permutation apart because no
    component is constant across all three ids: chapter is (2, 2, 10), section is
    (2, 10, 2), number is (2, 1, 1) -- each takes at least two distinct values, so
    every component genuinely varies and none of the three can sit out a
    comparison without affecting the outcome. Componentwise that is
    (2,2,2), (2,10,1), (10,2,1); sorted correctly by (chapter, section, number)
    that is V2.2.2, V2.10.1, V10.2.1. Measured by running each of the five wrong
    orderings of (chapter, section, number) as a mutation of _sort_key, every one
    of them produces an order that differs from the correct one, so this test
    catches all five.

    Records are written source-order V10.2.1, V2.2.2, V2.10.1 -- deliberately not
    already in the correct order -- so a regression that dropped the sort step
    entirely would not accidentally pass by inheriting a pre-sorted source file.
    """
    import json

    from owasp_kb.core.db import connect as _connect
    from owasp_kb.core.schema import create_schema as _create

    reqs = [
        {
            "chapter_id": "V10",
            "chapter_name": "C10",
            "section_id": "V10.2",
            "section_name": "S2",
            "req_id": "V10.2.1",
            "req_description": "text",
            "L": "1",
        },
        {
            "chapter_id": "V2",
            "chapter_name": "C2",
            "section_id": "V2.2",
            "section_name": "S2",
            "req_id": "V2.2.2",
            "req_description": "text",
            "L": "1",
        },
        {
            "chapter_id": "V2",
            "chapter_name": "C2",
            "section_id": "V2.10",
            "section_name": "S10",
            "req_id": "V2.10.1",
            "req_description": "text",
            "L": "1",
        },
    ]
    path = tmp_path / "component_order.json"
    path.write_text(json.dumps({"requirements": reqs}))
    conn = _connect(tmp_path / "component_order.sqlite")
    _create(conn)
    ingest_asvs(conn, path, version="5.0.0", license="CC-BY-SA-4.0")
    assert [r.req_id for r in Kb(conn).checklist("asvs")] == ["V2.2.2", "V2.10.1", "V10.2.1"]


def test_checklist_orders_by_the_stored_ordinal_not_by_id_syntax(kb):
    """The ordinal is what decides order. Rewriting it reverses the result --
    which no id-parsing ORDER BY could do, so this test distinguishes the two
    implementations rather than merely passing under both."""
    conn = kb._conn
    conn.execute(
        "UPDATE requirements SET ord = -ord WHERE pack_id ="
        " (SELECT id FROM packs WHERE name = 'asvs')"
    )
    conn.commit()
    assert [r.req_id for r in kb.checklist("asvs")] == ["V6.2.2", "V6.2.1", "V1.1.1"]


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


# -- catalogue --------------------------------------------------------


@pytest.fixture
def catalogue_conn(tmp_path):
    """The CWE fixture catalogue on its own.

    The catalogue methods touch neither the ASVS nor the cheat-sheet pack, so the
    smaller index makes a failure here point at the graph rather than at an ingest
    three packs wide. The connection is the fixture rather than the Kb because the
    depth-cap test has to write synthetic links.
    """
    conn = connect(tmp_path / "cwe.sqlite")
    create_schema(conn)
    ingest_cwe(conn, "tests/fixtures/cwec_sample.xml", version="4.20", license="LicenseRef-CWE-TOU")
    return conn


@pytest.fixture
def catalogue(catalogue_conn):
    return Kb(catalogue_conn)


def _child_links(conn, pairs):
    """Add synthetic cwe_child edges, for graph shapes the real catalogue has no
    example of -- a cycle, and a chain long enough to reach the depth cap."""
    conn.executemany(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('cwe', ?, 'cwe', ?, 'cwe_child', 'synthetic')",
        list(pairs),
    )


def _synthetic_chain(conn, edges):
    """A ChildOf chain of ``edges`` links whose foot is a real catalogue entry.

    Only the foot needs a catalogue_entries row: catalogue_related validates the id
    it is asked about, and CWE's graph legitimately points at ids outside the
    ingested set, which is what the rest of the chain stands in for.
    """
    chain = [f"CWE-9{i:03d}" for i in range(edges + 1)]
    pack_id = conn.execute("SELECT id FROM packs WHERE name = 'cwe'").fetchone()["id"]
    conn.execute(
        "INSERT INTO catalogue_entries (pack_id, entry_id, kind, name, abstraction, status,"
        " description) VALUES (?, ?, 'weakness', 'synthetic', 'Base', 'Draft', 'x')",
        (pack_id, chain[0]),
    )
    # strict=False: chain[1:] is deliberately one shorter, so the pairing is every
    # consecutive pair and the last node has no parent.
    _child_links(conn, zip(chain, chain[1:], strict=False))
    return chain


def test_catalogue_entry_returns_a_weakness_with_its_abstraction(catalogue):
    entry = catalogue.catalogue_entry("CWE-789")
    assert (entry.kind, entry.abstraction, entry.status) == ("weakness", "Variant", "Draft")
    assert "Memory Allocation" in entry.name
    assert entry.description


def test_catalogue_entry_returns_a_category_with_no_abstraction(catalogue):
    """CWE-320 is Obsolete and eight ASVS requirements cite it, so it has to be
    retrievable; a Category carries no Abstraction attribute, and that None is a
    fact about the entry rather than a gap in the row."""
    entry = catalogue.catalogue_entry("CWE-320")
    assert (entry.kind, entry.abstraction, entry.status) == ("category", None, "Obsolete")


def test_catalogue_entry_on_an_unknown_id_raises_naming_it(catalogue):
    with pytest.raises(KeyError, match="CWE-99999"):
        catalogue.catalogue_entry("CWE-99999")


def test_catalogue_related_returns_direct_edges_with_the_targets_abstraction(catalogue):
    edges = {e.to_id: e for e in catalogue.catalogue_related("CWE-789").edges}
    assert (edges["CWE-770"].rel, edges["CWE-770"].abstraction) == ("cwe_child", "Base")
    assert edges["CWE-476"].rel == "cwe_peer"


def test_catalogue_related_keeps_edges_pointing_outside_the_catalogue(catalogue):
    """The LEFT JOIN, at the level it lives on. All four of CWE-320's Has_Member
    targets are absent from this catalogue, so an inner join returns nothing at all
    for it."""
    edges = catalogue.catalogue_related("CWE-320").edges
    assert {e.to_id for e in edges} == {"CWE-322", "CWE-323", "CWE-324", "CWE-798"}
    assert {e.rel for e in edges} == {"cwe_member"}
    assert all(e.abstraction is None for e in edges)


def test_catalogue_related_ancestors_walks_the_chain_nearest_first(catalogue):
    """Measured chain: CWE-789 -> 770 -> 400/665 -> 664."""
    graph = catalogue.catalogue_related("CWE-789", ancestors=True)
    assert {e.rel for e in graph.edges} == {"cwe_child"}
    assert [e.to_id for e in graph.edges][0] == "CWE-770"
    assert {e.to_id for e in graph.edges} == {"CWE-770", "CWE-400", "CWE-665", "CWE-664"}
    assert graph.truncated is False


def test_catalogue_related_on_an_unknown_id_raises_rather_than_returning_no_edges(catalogue):
    """The opposite of Kb.related, deliberately. The catalogue's id space is closed,
    so an unknown id is a mis-cited number; for a requirement id, no edges is a real
    answer about the mapping. The guard lives here rather than in the tool so any
    caller of the core API inherits it."""
    with pytest.raises(KeyError, match="CWE-99999"):
        catalogue.catalogue_related("CWE-99999")
    with pytest.raises(KeyError, match="CWE-99999"):
        catalogue.catalogue_related("CWE-99999", ancestors=True)


def test_a_cycle_in_the_graph_terminates_the_walk(catalogue_conn):
    """The visited set, not the depth cap, is what makes the walk terminate. CWE's
    graph really does contain cycles, so a two-node one is walked here."""
    _child_links(catalogue_conn, [("CWE-789", "CWE-1004"), ("CWE-1004", "CWE-789")])
    graph = Kb(catalogue_conn).catalogue_related("CWE-789", ancestors=True)
    ids = [e.to_id for e in graph.edges]
    assert "CWE-1004" in ids
    assert "CWE-789" not in ids, "the entry walked from must not appear as its own ancestor"
    assert len(ids) == len(set(ids))
    assert graph.truncated is False


def test_an_ancestor_chain_deeper_than_the_cap_is_reported_as_truncated(catalogue_conn):
    """No real walk reaches the cap -- deepest is 5 levels against 20 -- but a chain
    cut silently below its Pillar looks exactly like one that shares a Base or a
    Class, which is the false 'related' the whole design exists to avoid. So the
    guard is exercised on a synthetic chain rather than left untested.

    This test cannot fail if MAX_ANCESTOR_DEPTH shrinks: the chain is built from the
    constant, so both move together. Shrinking it to 4 leaves the real catalogue
    truncating 19 entries with the whole suite green. That is what
    test_no_real_catalogue_entry_truncates_its_ancestor_walk is for; do not read this
    test as pinning the cap."""
    chain = _synthetic_chain(catalogue_conn, edges=MAX_ANCESTOR_DEPTH + 5)
    graph = Kb(catalogue_conn).catalogue_related(chain[0], ancestors=True)
    assert graph.truncated is True
    assert [e.to_id for e in graph.edges] == chain[1 : MAX_ANCESTOR_DEPTH + 1]


def test_a_chain_of_exactly_the_cap_is_complete_and_not_flagged(catalogue_conn):
    """The boundary the flag used to get wrong. A chain of exactly
    MAX_ANCESTOR_DEPTH edges is walked in full, but its last node is left in the
    frontier undiscovered-from, so ``bool(frontier)`` called it truncated. A false
    positive tells the agent to discard a comparison that is sound -- the flag's own
    harm, in reverse -- so the walk checks whether anything above the frontier is
    actually unvisited."""
    chain = _synthetic_chain(catalogue_conn, edges=MAX_ANCESTOR_DEPTH)
    graph = Kb(catalogue_conn).catalogue_related(chain[0], ancestors=True)
    assert [e.to_id for e in graph.edges] == chain[1:]
    assert len(graph.edges) == MAX_ANCESTOR_DEPTH
    assert graph.truncated is False


def test_a_cycle_at_the_cap_boundary_is_not_reported_as_truncated(catalogue_conn):
    """The other half of the same distinction: a frontier whose only parents are
    already visited is a cycle closing, not an ancestor missed."""
    chain = _synthetic_chain(catalogue_conn, edges=MAX_ANCESTOR_DEPTH)
    _child_links(catalogue_conn, [(chain[-1], chain[0])])
    graph = Kb(catalogue_conn).catalogue_related(chain[0], ancestors=True)
    assert [e.to_id for e in graph.edges] == chain[1:]
    assert graph.truncated is False


REAL_CATALOGUE = Path("data/cwe/cwec_v4.20.xml")


@pytest.mark.realdata
def test_no_real_catalogue_entry_truncates_its_ancestor_walk(tmp_path):
    """Pins MAX_ANCESTOR_DEPTH against the data instead of against itself.

    The two synthetic boundary tests above build their chains *from* the constant
    (``edges=MAX_ANCESTOR_DEPTH`` and ``+ 5``), so shrinking it shrinks the chains in
    lockstep and both stay green. Measured: MAX_ANCESTOR_DEPTH = 4 survives the entire
    suite while 19 real entries silently truncate, and 3 survives while 107 do. The
    suite enforced a floor of 3 -- incidentally, via the fixture's own 3-deep chain --
    for a catalogue that needs 5.

    Truncation is the one failure mode here that corrupts the claim rather than losing
    data: a chain cut below its Pillar reads exactly like one sharing a Base. So the
    assertion is over every entry, not a sample.
    """
    if not REAL_CATALOGUE.exists():
        pytest.skip(f"no catalogue at {REAL_CATALOGUE}; run the fetch step first")
    conn = connect(tmp_path / "real-cwe.sqlite")
    create_schema(conn)
    ingest_cwe(conn, REAL_CATALOGUE, version="4.20", license="LicenseRef-CWE-TOU")
    kb = Kb(conn)
    ids = [r["entry_id"] for r in conn.execute("SELECT entry_id FROM catalogue_entries")]
    assert len(ids) > 1000, f"only {len(ids)} entries ingested; the catalogue did not parse"
    truncated = [i for i in ids if kb.catalogue_related(i, ancestors=True).truncated]
    assert not truncated, (
        f"MAX_ANCESTOR_DEPTH = {MAX_ANCESTOR_DEPTH} truncates the ancestor walk for "
        f"{len(truncated)} of {len(ids)} real entries, e.g. {sorted(truncated)[:5]}. "
        "Every one of those reports a chain missing its coarsest end, which reads as "
        "a shared Base where there is none."
    )


def test_link_coverage_omits_requirement_counts_for_a_graph_that_has_no_requirements(
    catalogue_conn,
):
    """cwe_child, cwe_peer and cwe_member connect catalogue entries to each
    other, so no requirement is ever their from_id and 'covered 0 of 345' is a
    denominator that does not apply.

    kb_info's own description tells an agent to call it first and reads the
    coverage field as mapping completeness, so three relationships rendered at
    0% invite the conclusion that the CWE graph failed to load. It is complete:
    1,160 + 284 + 4,260 is every relationship in the catalogue.
    """
    coverage = {c.rel: c for c in Kb(catalogue_conn).info().link_coverage}

    for rel in ("cwe_child", "cwe_peer", "cwe_member"):
        assert coverage[rel].edges > 0, f"{rel} produced no edges at all"
        assert coverage[rel].requirements is None, (
            f"{rel} reports a requirement count; no requirement can reach it"
        )
        assert coverage[rel].total_requirements is None
        assert coverage[rel].share is None


def test_link_coverage_still_reports_a_rel_requirements_can_reach(kb):
    """The distinction must be structural, not 'the count came out zero'. A
    requirement-scoped mapping that resolved nothing is a real defect and has to
    stay visible as 0, not be reclassified as not-applicable.

    guidance is the sharp case: it is keyed on 'asvs_section' rather than
    'requirement', so a from_kind test would wrongly classify it as unscoped
    even though requirements reach it through their section id."""
    coverage = {c.rel: c for c in kb.info().link_coverage}
    for rel in ("cwe", "guidance"):
        assert coverage[rel].total_requirements is not None, f"{rel} lost its denominator"
        assert coverage[rel].requirements is not None
        assert coverage[rel].share is not None
