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


def test_exactly_seven_tools_are_exposed(tools):
    assert set(tools) == {
        "kb_info",
        "owasp_search",
        "owasp_outline",
        "owasp_get",
        "owasp_checklist",
        "owasp_related",
        "owasp_roster",
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
    assert {p["name"] for p in info["packs"]} == {"asvs", "cheatsheets"}


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


# -- size discipline --------------------------------------------------


def test_no_tool_response_exceeds_the_context_ceiling(tools):
    responses = [
        tools["kb_info"](),
        tools["owasp_search"]("password", limit=8),
        tools["owasp_outline"]("Authentication_Cheat_Sheet"),
        tools["owasp_get"]("Authentication_Cheat_Sheet"),
        tools["owasp_checklist"]("asvs"),
        tools["owasp_related"]("V6.2.1"),
    ]
    for response in responses:
        assert len(json.dumps(response)) < MAX_RESPONSE_CHARS


def test_every_response_is_json_serialisable(tools):
    """MCP transports JSON; a dataclass leaking through would fail at runtime."""
    json.dumps(tools["owasp_search"]("password"))
    json.dumps(tools["owasp_checklist"]("asvs"))
    json.dumps(tools["owasp_related"]("V6.2.1"))


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
