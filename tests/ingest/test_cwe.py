from pathlib import Path

import pytest

from owasp_kb.core.chunking import DEFAULT_MAX_TOKENS
from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.cwe import CWE_RELS, ingest_cwe

# Carved from data/cwe/cwec_v4.20.xml. The recipe recorded in the plan no longer
# reproduces this file -- it predates CWE-1240 and deletes Views outright, so
# re-running it reddens three tests. What is here and why:
#
#   weaknesses  118 119 120 664 665 770 789 1004 1187 1240
#   categories  255 320
#   views       1000
#
#   789             the worked example: a Variant, and one of the 390 weaknesses
#                   with no Extended_Description at all
#   120 119 118 664 the shortest ChildOf path from CWE-120 up to the Pillar
#                   CWE-664, so an ancestor walk has a full chain inside the
#                   fixture; drop CWE-118 and the chain stops dead at CWE-119
#   664             the only Pillar. 665, 770 and 400 give it descendants
#   1187 / 320      Deprecated and Obsolete respectively, and both must survive
#   1004            a second Variant, carrying a Diagram attribute
#   1240            918 tokens across six paragraphs -- the measured worst case
#                   for chunkability. Without it every chunk fits the embedder
#                   window under any flatten and the threshold tests pass
#                   vacuously
#   1000            a View whose two Has_Member children point at CWE-789 and
#                   CWE-664, both present, so a walk over Views would resolve and
#                   silently add edges rather than fail on dangling targets
FIXTURE = "tests/fixtures/cwec_sample.xml"
CATALOGUE = Path("data/cwe/cwec_v4.20.xml")


def _ingest(conn):
    return ingest_cwe(conn, FIXTURE, version="4.20", license="LicenseRef-CWE-TOU")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


@pytest.fixture
def ingested(conn):
    """The fixture catalogue, ingested once.

    Tests that re-ingest deliberately take ``conn`` and call ``_ingest`` themselves,
    so the three exercising idempotency and clearing are visibly different in shape
    from the sixteen that just read the result of one ingest.
    """
    _ingest(conn)
    return conn


# --- entries ----------------------------------------------------------------


def test_weaknesses_and_categories_are_both_ingested(conn):
    assert _ingest(conn) == 13
    kinds = dict(conn.execute("SELECT kind, COUNT(*) FROM catalogue_entries GROUP BY kind"))
    assert kinds == {"weakness": 11, "category": 2}


def test_a_weakness_carries_its_abstraction_and_a_category_does_not(ingested):
    """kind is load-bearing: a Category's graph is Has_Member rather than ChildOf,
    so treating them alike makes an ancestor comparison nonsense."""
    w = ingested.execute(
        "SELECT kind, abstraction FROM catalogue_entries WHERE entry_id='CWE-789'"
    ).fetchone()
    assert (w["kind"], w["abstraction"]) == ("weakness", "Variant")
    c = ingested.execute(
        "SELECT kind, abstraction FROM catalogue_entries WHERE entry_id='CWE-320'"
    ).fetchone()
    assert (c["kind"], c["abstraction"]) == ("category", None)


def test_a_pillar_is_recorded_as_such(ingested):
    """The Pillar finding depends on this: 35% of weakness pairs share some
    ancestor but only 5% share a non-Pillar one, so abstraction is what lets a
    caller tell a refinement from a coincidence."""
    row = ingested.execute(
        "SELECT abstraction FROM catalogue_entries WHERE entry_id='CWE-664'"
    ).fetchone()
    assert row["abstraction"] == "Pillar"


def test_an_entry_with_no_extended_description_ingests(ingested):
    """390 of 969 weaknesses have none, including CWE-789 itself. NOT NULL with no
    default would reject 40% of the catalogue."""
    row = ingested.execute(
        "SELECT extended_description FROM catalogue_entries WHERE entry_id='CWE-789'"
    ).fetchone()
    assert row["extended_description"] == ""


def test_deprecated_and_obsolete_entries_survive_ingest(ingested):
    """CWE-320 is Obsolete and eight ASVS requirements cite it. Filtering it out
    would make the enforcement reject a legitimate citation."""
    statuses = dict(
        ingested.execute(
            "SELECT entry_id, status FROM catalogue_entries "
            "WHERE entry_id IN ('CWE-320','CWE-1187')"
        )
    )
    assert statuses == {"CWE-320": "Obsolete", "CWE-1187": "Deprecated"}


def test_every_entry_is_searchable(ingested):
    """cwe_search needs chunks. Without them the pack is queryable by id only."""
    n = ingested.execute(
        "SELECT COUNT(*) FROM catalogue_entries WHERE chunk_id IS NOT NULL"
    ).fetchone()[0]
    assert n == 13


def test_chunk_id_points_at_the_description_chunk(ingested):
    """Only IS NOT NULL was pinned, so pointing chunk_id at the last chunk passed.
    CWE-1240 has three chunks -- one description and two extended -- which is what
    finally makes the distinction observable."""
    anchors = {
        r["anchor"]
        for r in ingested.execute(
            "SELECT s.anchor FROM catalogue_entries ce"
            " JOIN chunks ch ON ch.id = ce.chunk_id"
            " JOIN sections s ON s.id = ch.section_id"
        )
    }
    assert anchors == {"description"}


def test_the_document_title_carries_the_entry_id(ingested):
    """Deliberate departure from the plan's 'title = name', matching asvs.py's
    f"{chapter}: {chapter_name}". A retrieval hit shows its heading path, and
    'Memory Allocation with Excessive Size Value' alone does not say which CWE it
    is -- the id is the citable part."""
    row = ingested.execute(
        "SELECT d.title, ce.name FROM docs d"
        " JOIN catalogue_entries ce ON ce.entry_id = d.doc_key"
        " WHERE d.doc_key = 'CWE-789'"
    ).fetchone()
    assert row["title"] == "CWE-789: Memory Allocation with Excessive Size Value"
    assert row["name"] == "Memory Allocation with Excessive Size Value", (
        "the name column stays unprefixed; only the document title is composed"
    )


# --- flattening and chunking -------------------------------------------------


def test_nested_xhtml_prose_is_flattened_rather_than_lost(ingested):
    """Extended_Description wraps its prose in nested xhtml:p children, so el.text
    returns only the indentation before the first one and drops the description
    entirely. CWE-664 holds 426 characters across two paragraphs, none of it
    reachable from el.text.

    Both element shapes are asserted, because the flatten branches on whether an
    element has children and el.text happens to work for the childless one.
    """
    row = ingested.execute(
        "SELECT description, extended_description FROM catalogue_entries WHERE entry_id='CWE-664'"
    ).fetchone()
    # Nested shape: xhtml:p children, whitespace-only .text.
    extended = row["extended_description"]
    assert extended.startswith("Resources often have explicit instructions")
    assert len(extended) == 426
    # Childless shape: text directly on the element.
    assert row["description"].startswith("The product does not maintain or incorrectly maintains")


def test_a_long_extended_description_stays_chunkable(ingested):
    """A single-line flatten defeats the chunker. _split_oversized splits only on
    blank lines and otherwise returns the body as one part, so collapsing an entry
    to one line yields one oversized chunk the embedder silently truncates.

    CWE-1240 is the measured worst case in 4.20: 918 tokens over six paragraphs as
    one line, against a largest paragraph of 330. This is the sharpest pin
    available -- it reddens at 1 > 1 under a single-line flatten and at 0 > 1
    under el.text.
    """
    parts = ingested.execute(
        "SELECT ch.token_est FROM chunks ch"
        " JOIN sections s ON s.id = ch.section_id"
        " JOIN docs d ON d.id = s.doc_id"
        " WHERE d.doc_key = 'CWE-1240' AND s.anchor = 'extended-description'"
        " ORDER BY ch.id"
    ).fetchall()
    assert len(parts) > 1, "a 918-token extended description must not become one chunk"
    assert all(p["token_est"] <= DEFAULT_MAX_TOKENS for p in parts), (
        "an oversized chunk is silently truncated by the embedder"
    )


def test_no_chunk_from_the_fixture_exceeds_the_embedder_window(ingested):
    """Every chunk the fixture produces fits the window; the largest is 481 tokens.

    Named for the fixture, not the catalogue, because it is NOT a global guarantee:
    the real catalogue has 8 weaknesses whose extended description still lands in
    one oversized chunk, pinned by the test below and tracked in #38. Read as a
    catalogue-wide invariant this would assert something false.

    Within the fixture it is not vacuous -- CWE-1240 is 918 tokens as a single
    line, so this fails the moment the flatten stops preserving paragraphs.
    """
    biggest = ingested.execute("SELECT MAX(token_est) FROM chunks").fetchone()[0]
    assert biggest <= DEFAULT_MAX_TOKENS, f"largest chunk {biggest} exceeds the embedder window"


@pytest.mark.realdata
def test_the_real_catalogue_has_exactly_eight_oversized_chunks(conn):
    """Pins the residue of #38 so it cannot drift in either direction.

    Fails at 12 if the paragraph-preserving flatten regresses to a single line, and
    fails if #38 is fixed and the count drops -- which is the desired change, and
    one that should be noticed here rather than pass silently.

    The 8 survive because _split_oversized never size-checks its final block:
    chunk_markdown strips the body, so an entry whose largest paragraph comes last
    escapes the check entirely. CWE-1251's largest is last and it stays in one
    chunk; CWE-1240's is mid-document and it splits into three.
    """
    if not CATALOGUE.exists():
        pytest.skip(f"no catalogue at {CATALOGUE}; run the fetch step first")
    ingest_cwe(conn, CATALOGUE, version="4.20", license="LicenseRef-CWE-TOU")
    oversized = {
        r["doc_key"]: r["token_est"]
        for r in conn.execute(
            "SELECT d.doc_key, ch.token_est FROM chunks ch"
            " JOIN sections s ON s.id = ch.section_id"
            " JOIN docs d ON d.id = s.doc_id"
            " WHERE ch.token_est > ?",
            (DEFAULT_MAX_TOKENS,),
        )
    }
    assert len(oversized) == 8, (
        f"expected the 8 oversized chunks tracked in #38, got {len(oversized)}: "
        f"{sorted(oversized)}. If #38 is fixed, lower this count and note it here."
    )
    # The named entry is the mechanism rather than a coincidence: its largest
    # paragraph sits last, so it escapes the final-block check. The exact token
    # count is deliberately not asserted -- that would couple this to
    # estimate_tokens' len//4 and to MITRE's exact wording, so a reword in 4.21
    # would redden it with no indication why.
    assert oversized["CWE-1251"] > DEFAULT_MAX_TOKENS


# --- the graph ---------------------------------------------------------------


def test_childof_edges_are_ingested_as_cwe_child(ingested):
    parents = {
        r[0]
        for r in ingested.execute(
            "SELECT to_id FROM links WHERE rel='cwe_child' AND from_id='CWE-789'"
        )
    }
    assert "CWE-770" in parents


def test_a_non_childof_relationship_becomes_cwe_peer_not_cwe_child(ingested):
    """Mapping every Nature to cwe_child passes every other test in this file, yet
    it would make CanPrecede indistinguishable from a parent, and an ancestor walk
    would climb an edge that is a sequence rather than a refinement."""
    peers = {
        (r["from_id"], r["to_id"])
        for r in ingested.execute("SELECT from_id, to_id FROM links WHERE rel='cwe_peer'")
    }
    # Both are CanPrecede in 4.20; neither is a ChildOf edge.
    assert peers == {("CWE-120", "CWE-123"), ("CWE-789", "CWE-476")}
    children = {
        r["to_id"]
        for r in ingested.execute(
            "SELECT to_id FROM links WHERE rel='cwe_child' AND from_id='CWE-789'"
        )
    }
    assert "CWE-476" not in children, "a CanPrecede edge must not be recorded as a parent"


def test_category_membership_is_ingested_as_cwe_member(ingested):
    """The route out of a coarse mapping: CWE-320 is obsolete, and its members are
    where the specific weakness lives."""
    members = {
        r[0]
        for r in ingested.execute(
            "SELECT to_id FROM links WHERE rel='cwe_member' AND from_id='CWE-320'"
        )
    }
    assert len(members) == 4


def test_every_link_endpoint_is_kind_cwe(ingested):
    """from_kind/to_kind are what a later join filters on, and 'weakness' passes
    every other test here because nothing else asserts the value."""
    kinds = {tuple(r) for r in ingested.execute("SELECT DISTINCT from_kind, to_kind FROM links")}
    assert kinds == {("cwe", "cwe")}


def test_every_rel_produced_is_registered_for_clearing(ingested):
    """_clear_pack scopes by an exact rel IN list. A rel produced but absent from
    CWE_RELS leaves withdrawn edges of that rel surviving every rebuild, silently.

    Not vacuous in either direction: the fixture yields all three, so this also
    fails if a registered rel stops being produced at all.
    """
    assert {r[0] for r in ingested.execute("SELECT DISTINCT rel FROM links")} == set(CWE_RELS)


def test_a_view_is_neither_an_entry_nor_a_membership_edge(ingested):
    """Views are skipped structurally, not because a file happens to lack them.

    The fixture carries View 1000 with two Has_Member children pointing at CWE-789
    and CWE-664, both present as weaknesses, so a walk over Views would resolve and
    silently add edges rather than fail. Stake on the real catalogue: 5,024
    Has_Member elements, of which 764 sit under Views -- an 18% inflation of
    cwe_member with membership CWE never asserts.
    """
    assert (
        ingested.execute(
            "SELECT COUNT(*) FROM catalogue_entries WHERE entry_id='CWE-1000'"
        ).fetchone()[0]
        == 0
    ), "a View must not become a catalogue entry"
    members = ingested.execute("SELECT COUNT(*) FROM links WHERE rel='cwe_member'").fetchone()[0]
    # 15 from CWE-255 and 4 from CWE-320. The View's 2 must not appear.
    assert members == 19, "Has_Member under a View must not become a cwe_member edge"


# --- re-ingest ---------------------------------------------------------------


def test_ingest_is_idempotent(conn):
    """Both other packs are. A second run must not double the rows."""
    _ingest(conn)
    first = conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0]
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0] == first


def test_reingest_drops_an_edge_upstream_withdrew(conn):
    """The only real job of clearing links, and deleting that block passes every
    other test. Inserts are OR IGNORE, so without the delete a withdrawn edge
    survives every future rebuild."""
    _ingest(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('cwe', 'CWE-789', 'cwe', 'CWE-99999', 'cwe_child', 'stale.xml')"
    )
    conn.commit()
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM links WHERE to_id='CWE-99999'").fetchone()[0] == 0, (
        "a withdrawn edge must not survive a re-ingest"
    )


def test_reingest_preserves_links_owned_by_other_sources(conn):
    """Scoped by rel, so the ASVS->CWE mapping that links.py stores as rel='cwe'
    must be untouched. A prefix match like rel LIKE 'cwe%' would wipe it."""
    _ingest(conn)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('requirement', 'V6.1.1', 'cwe', 'CWE-789', 'cwe', 'mapping.json')"
    )
    conn.commit()
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM links WHERE rel='cwe'").fetchone()[0] == 1


# --- failing loudly ----------------------------------------------------------


def test_a_catalogue_that_yields_no_entries_is_rejected(conn, tmp_path):
    """A well-formed file that parses to nothing must not ingest as an empty pack.

    The namespace is derived from the root tag, so a root that is renamed or carries
    no namespace at all sends both findall calls looking under a prefix nothing
    matches: they return [], the pack row is still upserted, and the function would
    return 0 without complaint. Nothing downstream catches it -- integrity.py has no
    catalogue_entries check and does not expect any of the three cwe rels -- so an
    empty CWE pack would ship and every citation against it would fail to resolve.

    cheatsheets.py raises on an empty glob and asvs.py on a missing key; this is the
    equivalent, and the message names the namespace searched so the cause is
    readable rather than inferred.
    """
    unnamespaced = tmp_path / "cwec_no_namespace.xml"
    unnamespaced.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Weakness_Catalog Name="CWE" Version="4.99">'
        '<Weaknesses><Weakness ID="1" Name="Example" Abstraction="Base" Status="Draft">'
        "<Description>Text.</Description></Weakness></Weaknesses>"
        "</Weakness_Catalog>",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no Weakness or Category elements") as excinfo:
        ingest_cwe(conn, unnamespaced, version="4.99", license="LicenseRef-CWE-TOU")
    message = str(excinfo.value)
    assert "Weakness_Catalog" in message, "the message must name the namespace searched"
    assert unnamespaced.name in message, "and the file, so the cause is actionable"
