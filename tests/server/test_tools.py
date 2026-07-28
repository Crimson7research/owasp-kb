import json

import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.kb import Kb
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
from owasp_kb.server.tools import TOOL_TRIGGER_TOPICS, build_tools

MAX_RESPONSE_CHARS = 40_000


def _flat(result):
    """Every requirement in a grouped checklist response."""
    return [
        r
        for chapter in result["chapters"]
        for section in chapter["sections"]
        for r in section["requirements"]
    ]


@pytest.fixture
def tools(tmp_path):
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
    ingest_cwe(conn, "tests/fixtures/cwec_sample.xml", version="4.20", license="LicenseRef-CWE-TOU")
    ingest_guidance_links(conn, "tests/fixtures/IndexASVS_sample.md")
    ingest_cwe_links(
        conn,
        "tests/fixtures/cwe_mapping_sample.json",
        be_to_release_path="tests/fixtures/mapping_be_to_500_sample.yml",
    )
    ingest_supersedes_links(conn, "tests/fixtures/mapping_v5_to_v4_sample.yml")
    ingest_nist_links(conn, "tests/fixtures/nist_sample.md")
    return {t.__name__: t for t in build_tools(Kb(conn))}


# -- surface ----------------------------------------------------------


def test_exactly_nine_tools_are_exposed(tools):
    assert set(tools) == {
        "kb_info",
        "owasp_search",
        "owasp_outline",
        "owasp_get",
        "owasp_checklist",
        "owasp_related",
        "owasp_roster",
        "cwe_get",
        "cwe_related",
    }


def test_every_tool_has_a_docstring(tools):
    for name, fn in tools.items():
        assert fn.__doc__ and fn.__doc__.strip(), f"{name} has no description"


def test_search_description_lists_trigger_topics(tools):
    """Descriptions are the discovery mechanism: agents skip servers whose tool
    descriptions read as nouns."""
    doc = tools["owasp_search"].__doc__.lower()
    for topic in ("authentication", "injection", "cryptography", "authorization", "oauth"):
        assert topic in doc, f"{topic!r} missing from owasp_search description"
    assert "do not answer from memory" in doc


def test_trigger_topics_are_substantial():
    assert len(TOOL_TRIGGER_TOPICS) >= 20


def test_related_description_explains_the_guidance_relationship(tools):
    doc = tools["owasp_related"].__doc__.lower()
    assert "guidance" in doc and "cwe" in doc


# -- kb_info ----------------------------------------------------------


def test_kb_info_reports_mode_and_packs(tools):
    info = tools["kb_info"]()
    assert info["retrieval_mode"] == "lexical"
    assert {p["name"] for p in info["packs"]} == {"asvs", "cheatsheets", "cwe"}


def test_kb_info_exposes_link_coverage(tools):
    coverage = {c["rel"]: c for c in tools["kb_info"]()["link_coverage"]}
    assert coverage["guidance"]["total_requirements"] == 3


def test_kb_info_exposes_versions_for_citation(tools):
    versions = {p["name"]: p["version"] for p in tools["kb_info"]()["packs"]}
    assert versions["asvs"] == "5.0.0"


# -- owasp_search -----------------------------------------------------


def test_search_returns_citations(tools):
    result = tools["owasp_search"]("password")
    assert result["hits"]
    assert all(h["citation"] for h in result["hits"])


def test_search_no_match_returns_explicit_message_not_empty(tools):
    """A bare [] reads to an agent as 'no requirements apply'."""
    result = tools["owasp_search"]("zzzznotpresent")
    assert result["hits"] == []
    assert "no match" in result["message"].lower()
    assert "not that no security requirements apply" in result["message"].lower()


def test_search_truncates_long_excerpts(tools):
    for hit in tools["owasp_search"]("password", limit=5)["hits"]:
        assert len(hit["excerpt"]) <= 1300


def test_search_unknown_pack_returns_an_error_listing_packs(tools):
    result = tools["owasp_search"]("password", pack="nope")
    assert "error" in result
    assert "asvs" in result["error"]
    assert "hits" not in result


def test_search_respects_level_filter(tools):
    result = tools["owasp_search"]("password", pack="asvs", level="1")
    assert all(h["req_id"] == "V6.2.1" for h in result["hits"])


# -- outline / get ----------------------------------------------------


def test_outline_then_get_is_smaller_than_whole_document(tools):
    outline = tools["owasp_outline"]("Authentication_Cheat_Sheet")
    assert outline["sections"]
    anchor = outline["sections"][0]["anchor"]
    section = tools["owasp_get"]("Authentication_Cheat_Sheet", anchor=anchor)
    whole = tools["owasp_get"]("Authentication_Cheat_Sheet")
    assert len(section["text"]) < len(whole["text"])


def test_outline_unknown_doc_returns_an_error_with_suggestions(tools):
    result = tools["owasp_outline"]("Authentication_Cheatsheet")
    assert "error" in result
    assert "Authentication_Cheat_Sheet" in result["error"]


def test_get_returns_a_citation_including_the_anchor(tools):
    result = tools["owasp_get"]("Authentication_Cheat_Sheet", anchor="password-storage")
    assert result["citation"] == "Authentication_Cheat_Sheet#password-storage"


def test_get_unknown_anchor_returns_an_error_listing_anchors(tools):
    result = tools["owasp_get"]("Authentication_Cheat_Sheet", anchor="nope")
    assert "error" in result
    assert "password-storage" in result["error"]


# -- checklist --------------------------------------------------------


def test_checklist_returns_rows_with_levels_and_version(tools):
    result = tools["owasp_checklist"]("asvs", chapter="V6")
    assert [r["id"] for r in _flat(result)] == ["V6.2.1", "V6.2.2"]
    assert result["pack_version"] == "5.0.0"
    assert result["count"] == 2


def test_checklist_on_corpus_pack_returns_an_error(tools):
    result = tools["owasp_checklist"]("cheatsheets")
    assert "error" in result
    assert "corpus" in result["error"]


def test_checklist_defaults_to_asvs(tools):
    assert tools["owasp_checklist"]()["pack"] == "asvs"


def test_large_checklist_is_returned_in_full_with_a_note(tools, tmp_path):
    """Completeness beats brevity for a compliance enumeration; the note steers
    the caller to filter rather than silently dropping rows."""
    result = tools["owasp_checklist"]("asvs")
    assert result["count"] == len(_flat(result))
    assert "note" not in result  # the fixture has only 3 requirements


def test_checklist_never_truncates_its_rows(tools):
    result = tools["owasp_checklist"]("asvs")
    assert len(_flat(result)) == result["count"]


def test_checklist_level_is_cumulative_through_the_tool(tools):
    result = tools["owasp_checklist"]("asvs", level="2")
    assert {r["id"] for r in _flat(result)} == {"V1.1.1", "V6.2.1", "V6.2.2"}


def test_checklist_description_states_cumulative_levels(tools):
    """The description is what the agent reads; '183 at L2' invited the wrong call."""
    doc = tools["owasp_checklist"].__doc__.lower()
    assert "cumulative" in doc
    assert "253" in doc


def test_checklist_rejects_both_level_arguments_via_the_tool(tools):
    result = tools["owasp_checklist"]("asvs", level="2", level_exact="2")
    assert "error" in result


def test_grouped_response_contains_every_requirement(tools):
    """Completeness is the guarantee: the saving comes from removing repetition,
    never from dropping rows."""
    result = tools["owasp_checklist"]("asvs")
    assert len(_flat(result)) == result["count"]


def test_grouped_response_states_each_chapter_name_once(tools):
    result = tools["owasp_checklist"]("asvs")
    for chapter in result["chapters"]:
        assert chapter["name"]
        assert chapter["id"].startswith("V")
        for section in chapter["sections"]:
            assert section["name"]
            assert section["requirements"]


def test_grouped_response_preserves_requirement_order(tools):
    result = tools["owasp_checklist"]("asvs")
    assert [r["id"] for r in _flat(result)] == ["V1.1.1", "V6.2.1", "V6.2.2"]


def test_checklist_note_names_the_chapters_and_the_expected_total(tools, monkeypatch):
    """The note must be actionable: an agent needs a completion condition it can
    check, not just a warning that the response is big."""
    from owasp_kb.server import tools as tools_mod

    monkeypatch.setattr(tools_mod, "LARGE_CHECKLIST_ROWS", 1)
    result = tools["owasp_checklist"]("asvs")
    note = result["note"]
    assert "3" in note  # the expected total
    assert "V1" in note and "V6" in note  # the chapter ids to iterate
    assert "truncated" in note


# -- related ----------------------------------------------------------


def test_related_reaches_guidance_from_a_requirement(tools):
    edges = tools["owasp_related"]("V6.2.1")["edges"]
    assert any(e["to_id"] == "Authentication_Cheat_Sheet" for e in edges)


def test_related_unknown_id_returns_empty_edges_not_an_error(tools):
    """Unlike search, absence of edges is a real answer."""
    result = tools["owasp_related"]("V99.9.9")
    assert result["edges"] == []
    assert "error" not in result


def test_related_empty_result_explains_partial_coverage(tools):
    """A bare [] reads as 'no CWE applies'; upstream coverage is 59%."""
    result = tools["owasp_related"]("V1.1.1", rel="nist")
    assert result["edges"] == []
    assert "note" in result
    assert "not evidence" in result["note"].lower()


def test_related_with_edges_carries_no_note(tools):
    result = tools["owasp_related"]("V6.2.1", rel="cwe")
    assert result["edges"]
    assert "note" not in result


# -- cwe --------------------------------------------------------------


def test_cwe_get_returns_the_weakness(tools):
    r = tools["cwe_get"]("CWE-789")
    assert r["kind"] == "weakness"
    assert r["abstraction"] == "Variant"
    assert "Memory Allocation" in r["name"]
    assert r["description"]


def test_cwe_get_returns_a_category_with_its_status(tools):
    """CWE-320 is Obsolete and eight ASVS requirements cite it. An agent
    departing from that mapping needs to be able to say why."""
    r = tools["cwe_get"]("CWE-320")
    assert r["kind"] == "category"
    assert r["status"] == "Obsolete"
    assert r["abstraction"] is None


def test_cwe_get_states_a_categorys_absent_abstraction_rather_than_omitting_it(tools):
    """None must survive the dict and the JSON: a caller comparing how coarse two
    cited ids are has to see that a Category has no level, and a missing key reads
    as an oversight rather than as a fact about the entry."""
    r = tools["cwe_get"]("CWE-320")
    assert "abstraction" in r
    assert json.loads(json.dumps(r))["abstraction"] is None


def test_cwe_get_on_an_unknown_id_errors_and_names_it(tools):
    r = tools["cwe_get"]("CWE-99999")
    assert "error" in r
    assert "CWE-99999" in r["error"]


def test_cwe_related_returns_direct_edges_with_abstraction(tools):
    """Abstraction on every node is what lets a caller see that an overlap is
    only a Pillar."""
    edges = tools["cwe_related"]("CWE-789")["edges"]
    parent = next(e for e in edges if e["to_id"] == "CWE-770")
    assert parent["rel"] == "cwe_child"
    assert parent["abstraction"] == "Base"


def test_cwe_related_abstraction_is_the_targets_not_the_sources(tools):
    """CWE-789 is a Variant and CWE-770 a Base. If the join ever read the source's
    abstraction instead, every edge out of CWE-789 would say Variant and a chain
    comparison would be meaningless."""
    edges = tools["cwe_related"]("CWE-789")["edges"]
    assert tools["cwe_get"]("CWE-789")["abstraction"] == "Variant"
    assert {e["to_id"]: e["abstraction"] for e in edges}["CWE-770"] == "Base"


def test_cwe_related_ancestors_returns_the_whole_chain(tools):
    """Chains are short -- mean 3.2, max 13 -- so returning them whole avoids an
    agent recursing by hand across several calls."""
    ids = [e["to_id"] for e in tools["cwe_related"]("CWE-789", ancestors=True)["edges"]]
    assert {"CWE-770", "CWE-664"} <= set(ids)


def test_cwe_related_ancestors_follows_child_edges_only(tools):
    """CWE-789 PeerOf CWE-476 is a direct edge and must not become an ancestor:
    peers are what put cycles in the graph, and a peer's parents are not the cited
    weakness's parents."""
    direct = {e["to_id"]: e["rel"] for e in tools["cwe_related"]("CWE-789")["edges"]}
    assert direct["CWE-476"] == "cwe_peer"
    walked = tools["cwe_related"]("CWE-789", ancestors=True)["edges"]
    assert {e["rel"] for e in walked} == {"cwe_child"}
    assert "CWE-476" not in {e["to_id"] for e in walked}


def test_the_ancestor_chains_of_the_real_case_overlap_only_at_a_pillar(tools):
    """The finding that kept a refinement verdict out of the tools: CWE-789 and
    CWE-120 do share an ancestor, but it is a Pillar, and 35% of random weakness
    pairs share some ancestor against 5% sharing a non-Pillar one.

    Measured chains: CWE-789 -> 770 -> 400/665 -> 664, and CWE-120 -> 119 -> 118
    -> 664. Both intermediate Class entries are in the fixture for this reason."""
    a = {e["to_id"]: e for e in tools["cwe_related"]("CWE-789", ancestors=True)["edges"]}
    b = {e["to_id"]: e for e in tools["cwe_related"]("CWE-120", ancestors=True)["edges"]}
    shared = set(a) & set(b)
    assert shared == {"CWE-664"}
    assert a["CWE-664"]["abstraction"] == "Pillar"


def test_cwe_related_on_a_category_returns_its_members(tools):
    edges = tools["cwe_related"]("CWE-320")["edges"]
    assert {e["rel"] for e in edges} == {"cwe_member"}
    assert len(edges) == 4


def test_cwe_related_keeps_edges_whose_target_is_not_in_the_catalogue(tools):
    """The count above is of links rows, not of resolved entries. All four of
    CWE-320's Has_Member targets are outside this catalogue, so an inner join to
    read abstraction would answer 'no members' for an Obsolete Category that eight
    ASVS requirements cite -- the answer a caller is trying to get away from."""
    edges = tools["cwe_related"]("CWE-320")["edges"]
    assert {e["to_id"] for e in edges} == {"CWE-322", "CWE-323", "CWE-324", "CWE-798"}
    assert all(e["abstraction"] is None for e in edges)
    resolved = [e for e in edges if "error" not in tools["cwe_get"](e["to_id"])]
    assert resolved == [], "fixture premise: none of CWE-320's members is ingested"


def test_cwe_related_on_an_unknown_id_errors_rather_than_reporting_no_edges(tools):
    """An empty edge list for a hallucinated id reads as 'exists, unrelated'."""
    r = tools["cwe_related"]("CWE-99999")
    assert "error" in r
    assert "CWE-99999" in r["error"]
    assert "edges" not in r


def test_no_cwe_tool_emits_a_refinement_verdict(tools):
    """A graph check would have answered 'related' for CWE-789 vs CWE-120, the
    exact case that motivated this work -- and a verdict from a tool is trusted
    in a way an agent's own reasoning is not. The tools supply facts.

    Strengthened from the docstring-word check this replaced, which passed for any
    docstring containing 'not'. What is pinned instead is the response: the key
    sets are exact, so no derived judgement of any name can appear beside the
    facts, and the one docstring sentence that hands the call back to the caller
    must survive a rewrite."""
    responses = [
        tools["cwe_get"]("CWE-789"),
        tools["cwe_get"]("CWE-320"),
        tools["cwe_related"]("CWE-789"),
        tools["cwe_related"]("CWE-789", ancestors=True),
        tools["cwe_related"]("CWE-320"),
    ]
    for r in responses:
        assert set(r) <= {
            "entry_id",
            "kind",
            "name",
            "abstraction",
            "status",
            "description",
            "extended_description",
            "ancestors",
            "edges",
        }, f"unexpected key beside the facts: {sorted(set(r))}"
        for edge in r.get("edges", []):
            assert set(edge) == {"rel", "to_kind", "to_id", "abstraction", "source"}
    doc = " ".join(tools["cwe_related"].__doc__.lower().split())
    assert "your judgement, not this tool's" in doc
    assert "a shared pillar means almost nothing" in doc


def test_the_kb_catalogue_rels_match_what_the_ingest_writes():
    """core must not import ingest, so the three rel names are written twice. If
    they drift, catalogue_related returns nothing rather than failing."""
    from owasp_kb.core.kb import CATALOGUE_CHILD_REL, CATALOGUE_RELS
    from owasp_kb.ingest.packs.cwe import CWE_CHILD, CWE_RELS

    assert set(CATALOGUE_RELS) == set(CWE_RELS)
    assert CATALOGUE_CHILD_REL == CWE_CHILD


# -- size discipline --------------------------------------------------


def test_no_tool_response_exceeds_the_context_ceiling(tools):
    responses = [
        tools["kb_info"](),
        tools["owasp_search"]("password", limit=8),
        tools["owasp_outline"]("Authentication_Cheat_Sheet"),
        tools["owasp_get"]("Authentication_Cheat_Sheet"),
        tools["owasp_checklist"]("asvs"),
        tools["owasp_related"]("V6.2.1"),
        tools["cwe_get"]("CWE-1240"),  # the largest entry in the fixture catalogue
        tools["cwe_related"]("CWE-789", ancestors=True),
    ]
    for response in responses:
        assert len(json.dumps(response)) < MAX_RESPONSE_CHARS


def test_every_response_is_json_serialisable(tools):
    """MCP transports JSON; a dataclass leaking through would fail at runtime."""
    json.dumps(tools["owasp_search"]("password"))
    json.dumps(tools["owasp_checklist"]("asvs"))
    json.dumps(tools["owasp_related"]("V6.2.1"))
    json.dumps(tools["cwe_get"]("CWE-789"))
    json.dumps(tools["cwe_related"]("CWE-789", ancestors=True))


# -- roster -------------------------------------------------------------


def test_roster_tool_returns_a_complete_roster(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES", "V6": "N/A (verified)"},
        findings=[
            {
                "req_id": "V1.1.1",
                "chapter": "V1",
                "section": "V1.1",
                "verdict": "GAP",
                "evidence": "no canonicalisation",
                "file": "src/in.py",
                "line": 12,
                "cwe": "CWE-174",
                "trace": "untrusted path segment at src/in.py:12 reaches the filesystem call",
            }
        ],
    )
    assert result["complete"] is True
    assert result["count"] == 3
    assert sum(result["counts"].values()) == 3


def test_roster_tool_reports_a_missing_chapter_state_as_an_error(tools):
    """Scope and findings disagreeing must not be silently reconciled."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES"},
        findings=[],
    )
    assert "error" in result
    assert "V6" in result["error"]


def test_roster_tool_rejects_an_unverified_gap(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES", "V6": "APPLIES"},
        findings=[
            {
                "req_id": "V1.1.1",
                "chapter": "V1",
                "section": "V1.1",
                "verdict": "GAP",
                "evidence": "e",
                "file": "a.py",
                "line": 1,
                "cwe": "CWE-1",
            }
        ],
    )
    assert "error" in result
    assert "owasp-finding-verifier" in result["error"]


def test_roster_tool_reports_a_malformed_finding_as_an_error(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES", "V6": "APPLIES"},
        findings=[{"req_id": "V1.1.1"}],
    )
    assert "error" in result


def test_roster_tool_marks_unreported_requirements(tools):
    """A requirement nobody reported must not vanish from the roster."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES", "V6": "APPLIES"},
        findings=[],
    )
    assert result["counts"]["INSUFFICIENT EVIDENCE"] == 3


def test_roster_tool_description_states_it_enforces_completeness(tools):
    doc = tools["owasp_roster"].__doc__.lower()
    assert "complete" in doc
    assert "insufficient evidence" in doc


def test_roster_tool_rejects_a_finding_citing_an_excluded_report(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states={"V1": "APPLIES", "V6": "APPLIES"},
        excluded=["docs/security/prior-audit.md"],
        findings=[
            {
                "req_id": "V1.1.1",
                "chapter": "V1",
                "section": "V1.1",
                "verdict": "GAP",
                "evidence": "see docs/security/prior-audit.md",
                "file": "a.py",
                "line": 1,
                "cwe": "CWE-1",
                "trace": "t",
            }
        ],
    )
    assert "error" in result
    assert "docs/security/prior-audit.md" in result["error"]


def test_roster_tool_response_is_json_serialisable(tools):
    """MCP transports JSON; a dataclass leaking through would fail at runtime."""
    import json

    json.dumps(
        tools["owasp_roster"](
            pack="asvs",
            chapter_states={"V1": "APPLIES", "V6": "APPLIES"},
            findings=[
                {
                    "req_id": "V6.2.1",
                    "chapter": "V6",
                    "section": "V6.2",
                    "verdict": "GAP",
                    "evidence": "e",
                    "file": "a.py",
                    "line": 1,
                    "cwe": "CWE-521",
                    "trace": "t",
                }
            ],
        )
    )


def _gap(req_id, chapter, section, **kw):
    """A minimally valid GAP finding for the roster: traced, located, in scope."""
    base = {
        "req_id": req_id,
        "chapter": chapter,
        "section": section,
        "verdict": "GAP",
        "evidence": "e",
        "file": "a.py",
        "line": 1,
        "cwe": "CWE-1",
        "trace": "t",
    }
    base.update(kw)
    return base


STATES = {"V1": "APPLIES", "V6": "APPLIES"}


def test_a_remediation_naming_an_unknown_document_is_rejected(tools):
    """A citation that points nowhere looks exactly like one that points
    somewhere. SearchHit already rejects an uncitable hit at construction; a
    finding's remediation field had no equivalent guard."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.1", "V6", "V6.2", remediation="Nonexistent_Cheat_Sheet#foo")],
    )
    assert "error" in result
    assert "Nonexistent_Cheat_Sheet" in result["error"]
    assert "V6.2.1" in result["error"]


def test_a_remediation_naming_an_unknown_anchor_is_rejected(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap("V6.2.1", "V6", "V6.2", remediation="Authentication_Cheat_Sheet#no-such-section")
        ],
    )
    assert "error" in result
    assert "no-such-section" in result["error"]
    # the message must help: Kb.get lists the anchors that do exist
    assert "password-storage" in result["error"]
    assert "V6.2.1" in result["error"]


def test_a_resolvable_remediation_is_accepted(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap("V6.2.1", "V6", "V6.2", remediation="Authentication_Cheat_Sheet#password-storage")
        ],
    )
    assert "error" not in result
    assert result["complete"] is True


def test_a_document_level_remediation_needs_no_anchor(tools):
    """The guidance mapping is document-level -- a finder attaching an edge has no
    anchor to give, and that is a valid citation."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.1", "V6", "V6.2", remediation="Authentication_Cheat_Sheet")],
    )
    assert "error" not in result


def test_a_finding_with_no_remediation_is_still_accepted(tools):
    """13 of 345 requirements have no guidance edge. Omitting the field is correct
    there; requiring one would force an invented citation."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.1", "V6", "V6.2")],
    )
    assert "error" not in result


def test_a_quote_present_in_the_cited_section_is_accepted(tools):
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap(
                "V6.2.1",
                "V6",
                "V6.2",
                remediation="Authentication_Cheat_Sheet#password-storage",
                remediation_quote="Store passwords with argon2id.",
            )
        ],
    )
    assert "error" not in result


def test_a_quote_absent_from_the_cited_section_is_rejected(tools):
    """Claiming to have read a section and being unable to quote it is the case
    this catches -- an anchor that merely exists proves nothing about whether the
    agent navigated to it or recalled it."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap(
                "V6.2.1",
                "V6",
                "V6.2",
                remediation="Authentication_Cheat_Sheet#password-storage",
                remediation_quote="Use bcrypt with a work factor of 12.",
            )
        ],
    )
    assert "error" in result
    assert "V6.2.1" in result["error"]
    assert "password-storage" in result["error"]


def test_a_quote_differing_only_in_whitespace_is_accepted(tools):
    """Kb.get joins chunks with a blank line and chunking splits at 512 tokens, so
    a quote spanning a boundary carries whitespace the source does not. Without
    normalisation this rule would reject correct quotes, which is worse than not
    having it."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap(
                "V6.2.1",
                "V6",
                "V6.2",
                remediation="Authentication_Cheat_Sheet#password-storage",
                remediation_quote="Store   passwords\n\nwith  argon2id.",
            )
        ],
    )
    assert "error" not in result


def test_a_quote_without_a_remediation_is_rejected(tools):
    """A quote with nothing to check it against is a claim with no referent."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.1", "V6", "V6.2", remediation_quote="Store passwords with argon2id.")],
    )
    assert "error" in result
    assert "remediation" in result["error"]


def test_the_response_reports_the_corpus_cwe_beside_the_cited_one(tools):
    """44% of cited CWE ids in a real report were model-supplied and
    indistinguishable from mapped ones. Returning the mapping lets the report
    render both instead of silently presenting one as the other."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.1", "V6", "V6.2", cwe="CWE-789")],
    )
    finding = result["findings"][0]
    assert finding["cwe"] == "CWE-789"
    assert finding["cwe_corpus"] == ["CWE-521"]


def test_cwe_corpus_is_empty_when_the_mapping_has_none(tools):
    """cwe coverage is 204/345. An empty list says the mapping is silent, which is
    different from the model having agreed with it."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V1.1.1", "V1", "V1.1", cwe="CWE-311")],
    )
    assert result["findings"][0]["cwe_corpus"] == []


def test_cwe_corpus_lists_every_mapped_id(tools):
    """A requirement can map to several. V6.2.2 maps to two."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[_gap("V6.2.2", "V6", "V6.2", cwe="CWE-307")],
    )
    assert sorted(result["findings"][0]["cwe_corpus"]) == ["CWE-307", "CWE-521"]


def test_cwe_corpus_unions_the_mappings_of_a_merged_finding(tools):
    """Two findings at the same (file, line, cwe) merge into one covering both
    requirements. Its corpus mapping is the union -- one defect, two requirements,
    and a reader wants both mappings."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap("V6.2.1", "V6", "V6.2", cwe="CWE-789"),
            _gap("V6.2.2", "V6", "V6.2", cwe="CWE-789"),
        ],
    )
    assert len(result["findings"]) == 1, "same file/line/cwe should merge"
    assert sorted(result["findings"][0]["cwe_corpus"]) == ["CWE-307", "CWE-521"]


def test_a_quote_matching_only_after_normalising_the_section_is_accepted(tools):
    """The cheat sheet source wraps 'Protecting Against Automated Attacks' across
    two lines, so the indexed section text carries a literal newline the
    quote-as-written does not. Normalisation must apply to the section side as
    well as the quote side -- comparing a normalised quote against the raw
    section would reject this correct quote."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap(
                "V6.2.1",
                "V6",
                "V6.2",
                remediation="Authentication_Cheat_Sheet#protecting-against-automated-attacks",
                remediation_quote=(
                    "Defend against credential stuffing and brute force with rate "
                    "limiting and anti-automation controls."
                ),
            )
        ],
    )
    assert "error" not in result


def test_a_read_citation_validates_even_without_a_guidance_edge(tools):
    """The V1.4.1 case from the earlier assessment: the corpus maps no guidance to that
    requirement, and the agent navigated to a section and read it anyway. That is a
    better citation than the mapping would give, and it must pass.

    V1.1.1 has no guidance edge in the fixture index, mirroring V1.4.1."""
    result = tools["owasp_roster"](
        pack="asvs",
        chapter_states=STATES,
        findings=[
            _gap(
                "V1.1.1",
                "V1",
                "V1.1",
                remediation="Authentication_Cheat_Sheet#password-storage",
                remediation_quote="Store passwords with argon2id.",
            )
        ],
    )
    assert "error" not in result
    assert result["complete"] is True


def test_the_roster_docstring_documents_the_citation_rules(tools):
    """The docstring is what an agent reads to know a field exists and a rule
    applies. Both rules shipped enforced and undocumented, so an agent would have
    hit a citation rejection it had no way to anticipate."""
    doc = tools["owasp_roster"].__doc__
    assert "remediation_quote" in doc
    assert "cwe_corpus" in doc
    assert "must" in doc and "resolve" in doc


def test_kb_info_reports_the_server_version(tools):
    """A reconnect reports success while serving a stale image. This makes
    'which build answered' one call instead of comparing a Docker timestamp
    against git log. See #13."""
    from owasp_kb import __version__

    assert tools["kb_info"]()["server_version"] == __version__


def test_the_server_version_matches_the_plugin(tools):
    """Lockstep: the plugin and the server it ships beside carry one number, so a
    mismatch at runtime means a stale image rather than an ambiguity."""
    import json
    from pathlib import Path

    plugin = json.loads(Path("plugins/owasp-kb/.claude-plugin/plugin.json").read_text())
    assert tools["kb_info"]()["server_version"] == plugin["version"]
