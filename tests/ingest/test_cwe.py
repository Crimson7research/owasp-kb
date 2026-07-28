from pathlib import Path

import pytest

from owasp_kb.core.chunking import DEFAULT_MAX_TOKENS
from owasp_kb.core.db import connect
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.cwe import ingest_cwe

FIXTURE = "tests/fixtures/cwec_sample.xml"


@pytest.fixture
def conn():
    c = connect(":memory:")
    create_schema(c)
    return c


def _ingest(c):
    return ingest_cwe(c, FIXTURE, version="4.20", license="LicenseRef-CWE-TOU")


def test_weaknesses_and_categories_are_both_ingested(conn):
    _ingest(conn)
    kinds = dict(conn.execute("SELECT kind, COUNT(*) FROM catalogue_entries GROUP BY kind"))
    assert kinds == {"weakness": 11, "category": 2}


def test_a_weakness_carries_its_abstraction_and_a_category_does_not(conn):
    """kind is load-bearing: a Category's graph is Has_Member rather than ChildOf,
    so treating them alike makes an ancestor comparison nonsense."""
    _ingest(conn)
    w = conn.execute(
        "SELECT kind, abstraction FROM catalogue_entries WHERE entry_id='CWE-789'"
    ).fetchone()
    assert (w["kind"], w["abstraction"]) == ("weakness", "Variant")
    c = conn.execute(
        "SELECT kind, abstraction FROM catalogue_entries WHERE entry_id='CWE-320'"
    ).fetchone()
    assert (c["kind"], c["abstraction"]) == ("category", None)


def test_a_pillar_is_recorded_as_such(conn):
    """The Pillar finding depends on this: 35% of weakness pairs share some
    ancestor but only 5% share a non-Pillar one, so abstraction is what lets a
    caller tell a refinement from a coincidence."""
    _ingest(conn)
    row = conn.execute(
        "SELECT abstraction FROM catalogue_entries WHERE entry_id='CWE-664'"
    ).fetchone()
    assert row["abstraction"] == "Pillar"


def test_an_entry_with_no_extended_description_ingests(conn):
    """390 of 969 weaknesses have none, including CWE-789 itself. NOT NULL with no
    default would reject 40% of the catalogue."""
    _ingest(conn)
    row = conn.execute(
        "SELECT extended_description FROM catalogue_entries WHERE entry_id='CWE-789'"
    ).fetchone()
    assert row["extended_description"] == ""


def test_nested_xhtml_prose_is_flattened_rather_than_lost(conn):
    """Extended_Description wraps its prose in nested xhtml:p elements, so reading
    el.text yields only the indentation before the first child and drops the whole
    description. Measured on 4.20: CWE-664's Extended_Description holds 426
    characters across two paragraphs, none of it reachable from el.text.

    Without this the flatten is unpinned -- replacing it with el.text leaves all
    the other assertions in this file green, because the element el.text does work
    for is the common one. Both shapes are asserted here for that reason. The
    flatten branches on whether an element has children, and 4.20 splits 1,689
    with none against 284 with some, across 1,973 elements in total. That split is
    not the same as a split by tag: every Description (969) and Summary (422) is
    childless, while Extended_Description (582) is mixed -- 284 nested and 298 not.
    """
    _ingest(conn)
    row = conn.execute(
        "SELECT description, extended_description FROM catalogue_entries WHERE entry_id='CWE-664'"
    ).fetchone()
    # Nested shape: xhtml:p children, whitespace-only .text.
    extended = row["extended_description"]
    assert extended.startswith("Resources often have explicit instructions")
    assert len(extended) == 426
    # Unnested shape: text directly on the element, no children.
    assert row["description"].startswith("The product does not maintain or incorrectly maintains")


def test_a_long_extended_description_stays_chunkable(conn):
    """A single-line flatten defeats the chunker. _split_oversized splits only on
    blank lines and otherwise returns the body as one part, so collapsing an entry
    to one line yields one oversized chunk that the embedder silently truncates at
    512 tokens.

    CWE-1240 is the measured worst case in 4.20: 918 tokens over six paragraphs as
    one line, versus a largest paragraph of 330. It is in the fixture solely to pin
    this -- the other ten weaknesses top out at CWE-664's 106 tokens, so without it
    a threshold assertion would pass whichever flatten were used.

    This is the sharpest pin available: it reddens at 1 > 1 under a single-line
    flatten and at 0 > 1 under el.text.
    """
    _ingest(conn)
    parts = conn.execute(
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


def test_no_chunk_from_the_fixture_exceeds_the_embedder_window(conn):
    """Every chunk the fixture produces fits the window: largest is 481 tokens.

    Named for the fixture, not the catalogue, because it is NOT a global guarantee.
    The real catalogue has 8 weaknesses whose extended description still lands in
    one oversized chunk -- see the exact-count test below and #38. Read as a
    catalogue-wide invariant this would be asserting something false.

    Within the fixture it is not vacuous: CWE-1240 is 918 tokens as a single line,
    so this fails at 918 the moment the flatten stops preserving paragraphs.
    """
    _ingest(conn)
    biggest = conn.execute("SELECT MAX(token_est) FROM chunks").fetchone()[0]
    assert biggest <= DEFAULT_MAX_TOKENS, f"largest chunk {biggest} exceeds the embedder window"


def test_the_real_catalogue_has_exactly_eight_oversized_chunks():
    """Pins the residue of #38 so it cannot drift in either direction.

    Fails at 12 if the paragraph-preserving flatten regresses to a single line.
    Fails if #38 is fixed and the count drops -- which is the desired change, and
    one that should be noticed here rather than pass silently.

    The 8 survive because _split_oversized never size-checks its final block:
    chunk_markdown strips the body, so an entry whose largest paragraph comes last
    escapes the check entirely. CWE-1251's largest is last and it stays in one
    880-token chunk; CWE-1240's is mid-document and it splits into three.
    """
    catalogue = Path("data/cwe/cwec_v4.20.xml")
    if not catalogue.exists():
        pytest.skip("real data/ catalogue not fetched in this environment")
    conn = connect(":memory:")
    create_schema(conn)
    ingest_cwe(conn, catalogue, version="4.20", license="LicenseRef-CWE-TOU")
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
    assert len(oversized) == 8, f"expected the 8 tracked in #38, got {sorted(oversized)}"
    assert oversized["CWE-1251"] == 880


def test_deprecated_and_obsolete_entries_survive_ingest(conn):
    """CWE-320 is Obsolete and eight ASVS requirements cite it. Filtering it out
    would make the enforcement reject a legitimate citation."""
    _ingest(conn)
    statuses = dict(
        conn.execute(
            "SELECT entry_id, status FROM catalogue_entries "
            "WHERE entry_id IN ('CWE-320','CWE-1187')"
        )
    )
    assert statuses == {"CWE-320": "Obsolete", "CWE-1187": "Deprecated"}


def test_childof_edges_are_ingested_as_cwe_child(conn):
    _ingest(conn)
    parents = {
        r[0]
        for r in conn.execute("SELECT to_id FROM links WHERE rel='cwe_child' AND from_id='CWE-789'")
    }
    assert "CWE-770" in parents


def test_a_non_childof_relationship_becomes_cwe_peer_not_cwe_child(conn):
    """Mapping every Nature to cwe_child passes every other test in this file, yet
    it would make CanPrecede indistinguishable from a parent, and an ancestor walk
    would climb an edge that is a sequence rather than a refinement."""
    _ingest(conn)
    peers = {
        (r["from_id"], r["to_id"])
        for r in conn.execute("SELECT from_id, to_id FROM links WHERE rel='cwe_peer'")
    }
    # Both are CanPrecede in 4.20; neither is a ChildOf edge.
    assert peers == {("CWE-120", "CWE-123"), ("CWE-789", "CWE-476")}
    children = {
        r["to_id"]
        for r in conn.execute("SELECT to_id FROM links WHERE rel='cwe_child' AND from_id='CWE-789'")
    }
    assert "CWE-476" not in children, "a CanPrecede edge must not be recorded as a parent"


def test_every_link_endpoint_is_kind_cwe(conn):
    """from_kind/to_kind are what a later join filters on, and 'weakness' passes
    every other test here because nothing else asserts the value."""
    _ingest(conn)
    kinds = {tuple(r) for r in conn.execute("SELECT DISTINCT from_kind, to_kind FROM links")}
    assert kinds == {("cwe", "cwe")}


def test_chunk_id_points_at_the_description_chunk(conn):
    """Only IS NOT NULL was pinned, so pointing chunk_id at the last chunk passed.
    CWE-1240 has three chunks -- one description and two extended -- which is what
    finally makes the distinction observable."""
    _ingest(conn)
    anchors = {
        r["anchor"]
        for r in conn.execute(
            "SELECT s.anchor FROM catalogue_entries ce"
            " JOIN chunks ch ON ch.id = ce.chunk_id"
            " JOIN sections s ON s.id = ch.section_id"
        )
    }
    assert anchors == {"description"}


def test_a_view_is_neither_an_entry_nor_a_membership_edge(conn):
    """Views are skipped structurally, not because a file happens to lack them.

    The fixture carries View 1000 with two Has_Member children pointing at CWE-789
    and CWE-664, both present as weaknesses, so a walk over Views would resolve and
    silently add edges rather than fail. Stake on the real catalogue: 5,024
    Has_Member elements, of which 764 sit under Views -- an 18% inflation of
    cwe_member with membership CWE never asserted.
    """
    _ingest(conn)
    assert (
        conn.execute("SELECT COUNT(*) FROM catalogue_entries WHERE entry_id='CWE-1000'").fetchone()[
            0
        ]
        == 0
    ), "a View must not become a catalogue entry"
    members = conn.execute("SELECT COUNT(*) FROM links WHERE rel='cwe_member'").fetchone()[0]
    # 15 from CWE-255 and 4 from CWE-320. The View's 2 must not appear.
    assert members == 19, "Has_Member under a View must not become a cwe_member edge"


def test_the_document_title_carries_the_entry_id(conn):
    """Deliberate departure from 'title = name', matching asvs.py's
    f"{chapter}: {chapter_name}". A retrieval hit shows its heading path, and
    'Memory Allocation with Excessive Size Value' alone does not say which CWE it
    is -- the id is the citable part."""
    _ingest(conn)
    row = conn.execute(
        "SELECT d.title, ce.name FROM docs d"
        " JOIN catalogue_entries ce ON ce.entry_id = d.doc_key"
        " WHERE d.doc_key = 'CWE-789'"
    ).fetchone()
    assert row["title"] == "CWE-789: Memory Allocation with Excessive Size Value"
    assert row["name"] == "Memory Allocation with Excessive Size Value", (
        "the name column stays unprefixed; only the document title is composed"
    )


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


def test_category_membership_is_ingested_as_cwe_member(conn):
    """The route out of a coarse mapping: CWE-320 is obsolete, and its members are
    where the specific weakness lives."""
    _ingest(conn)
    members = {
        r[0]
        for r in conn.execute(
            "SELECT to_id FROM links WHERE rel='cwe_member' AND from_id='CWE-320'"
        )
    }
    assert len(members) == 4


def test_every_entry_is_searchable(conn):
    """cwe_search needs chunks. Without them the pack is queryable by id only."""
    _ingest(conn)
    n = conn.execute(
        "SELECT COUNT(*) FROM catalogue_entries WHERE chunk_id IS NOT NULL"
    ).fetchone()[0]
    assert n == 13


def test_ingest_is_idempotent(conn):
    """Both other packs are. A second run must not double the rows."""
    _ingest(conn)
    first = conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0]
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0] == first
