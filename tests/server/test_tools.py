import json

import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.kb import Kb
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import ingest_cwe_links, ingest_guidance_links
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.server.tools import TOOL_TRIGGER_TOPICS, build_tools

MAX_RESPONSE_CHARS = 40_000


@pytest.fixture
def tools(tmp_path):
    conn = connect(tmp_path / "kb.sqlite")
    create_schema(conn)
    ingest_asvs(conn, "tests/fixtures/asvs_sample.flat.json",
                version="5.0.0", license="CC-BY-SA-4.0")
    ingest_cheatsheets(conn, "tests/fixtures/cheatsheets", version="20260724",
                       commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
                       license="CC-BY-SA-4.0")
    ingest_guidance_links(conn, "tests/fixtures/IndexASVS_sample.md")
    ingest_cwe_links(conn, "tests/fixtures/cwe_mapping_sample.json",
                     be_to_release_path="tests/fixtures/mapping_be_to_500_sample.yml")
    return {t.__name__: t for t in build_tools(Kb(conn))}


# -- surface ----------------------------------------------------------

def test_exactly_six_tools_are_exposed(tools):
    assert set(tools) == {
        "kb_info", "owasp_search", "owasp_outline",
        "owasp_get", "owasp_checklist", "owasp_related",
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
    assert [r["req_id"] for r in result["requirements"]] == ["V6.2.1", "V6.2.2"]
    assert result["pack_version"] == "5.0.0"
    assert result["count"] == 2


def test_checklist_on_corpus_pack_returns_an_error(tools):
    result = tools["owasp_checklist"]("cheatsheets")
    assert "error" in result
    assert "corpus" in result["error"]


def test_checklist_defaults_to_asvs(tools):
    assert tools["owasp_checklist"]()["pack"] == "asvs"


# -- related ----------------------------------------------------------

def test_related_reaches_guidance_from_a_requirement(tools):
    edges = tools["owasp_related"]("V6.2.1")["edges"]
    assert any(e["to_id"] == "Authentication_Cheat_Sheet" for e in edges)


def test_related_unknown_id_returns_empty_edges_not_an_error(tools):
    """Unlike search, absence of edges is a real answer."""
    result = tools["owasp_related"]("V99.9.9")
    assert result["edges"] == []
    assert "error" not in result


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
