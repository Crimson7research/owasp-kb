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
    the other assertions in this file green, because Description and Summary
    happen to be unnested while Extended_Description is not. Both element shapes
    are asserted here for that reason: 4.20 has 1,689 unnested Description and
    Summary elements against 284 nested Extended_Description elements.
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

    Scoped to this entry rather than asserting a ceiling over every chunk, which
    would overclaim: 8 of the 969 weaknesses still produce one oversized chunk on
    the real catalogue, because _split_oversized never size-checks its final block
    and chunk_markdown strips the body, so an entry whose largest paragraph comes
    last escapes the check. That is a chunking limitation shared with the other
    packs, not something this ingest can close.
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
