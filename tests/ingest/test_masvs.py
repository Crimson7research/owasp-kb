import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.integrity import EMBEDDER_MAX_TOKENS
from owasp_kb.core.registry import get_pack
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.masvs import ingest_masvs

FIXTURE = "tests/fixtures/masvs_sample.yaml"

# A second, small fixture rather than a group added to FIXTURE: FIXTURE's counts
# (4 controls, 2 docs, a hard-coded ordinal list) are asserted on directly by
# several tests above, and a group added there for this purpose would force
# every one of those to change for a concern they do not otherwise care about.
LONG_OVERVIEW_FIXTURE = "tests/fixtures/masvs_long_overview.yaml"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


def _ingest(conn):
    return ingest_masvs(conn, FIXTURE, version="2.1.0", license="CC-BY-SA-4.0")


def test_ingests_every_control(conn):
    assert _ingest(conn) == 4
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 4


def test_registers_pack_as_checklist(conn):
    _ingest(conn)
    pack = get_pack(conn, "masvs")
    assert pack.type == "checklist"
    assert pack.version == "2.1.0"
    assert pack.license == "CC-BY-SA-4.0"
    assert pack.commit_sha is None


def test_the_version_comes_from_the_lock_not_the_document(conn):
    """The fixture stamps v9.9.9, a plausible wrong value. The lock is the
    authority: reading metadata.version would let a re-fetch move every
    citation's version, and the asset's own `v`-prefixed string is not even
    string-equal to the `2.1.0` the lock and the citations use."""
    _ingest(conn)
    assert get_pack(conn, "masvs").version == "2.1.0"


def test_the_group_fills_both_chapter_and_section(conn):
    """MASVS is two-tier. Stating that plainly beats synthesising a middle tier."""
    _ingest(conn)
    row = conn.execute(
        "SELECT chapter_id, chapter_name, section_id, section_name FROM requirements"
        " WHERE req_id = 'MASVS-STORAGE-1'"
    ).fetchone()
    assert row["chapter_id"] == "MASVS-STORAGE"
    assert row["section_id"] == "MASVS-STORAGE"
    assert row["chapter_name"] == "Storage"
    assert row["section_name"] == "Storage"


def test_controls_carry_no_level(conn):
    _ingest(conn)
    levels = [r[0] for r in conn.execute("SELECT level FROM requirements")]
    assert levels == [None, None, None, None]


def test_requirement_text_carries_the_description_not_only_the_statement(conn):
    """The statement alone is one sentence, which is the coarseness that made an
    agent reach for an ASVS requirement instead."""
    _ingest(conn)
    text = conn.execute(
        "SELECT text FROM requirements WHERE req_id = 'MASVS-STORAGE-1'"
    ).fetchone()[0]
    assert "The app securely stores sensitive data." in text
    assert "independently of the target location" in text


def test_ordinals_follow_the_document(conn):
    _ingest(conn)
    order = [r[0] for r in conn.execute("SELECT req_id FROM requirements ORDER BY ord")]
    assert order == [
        "MASVS-STORAGE-1",
        "MASVS-STORAGE-2",
        "MASVS-CRYPTO-1",
        "MASVS-CRYPTO-2",
    ]


def test_each_control_gets_a_searchable_chunk(conn):
    _ingest(conn)
    hits = conn.execute(
        "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH 'cryptographic'"
    ).fetchall()
    assert hits


def test_the_group_description_is_retrievable_and_has_no_requirement(conn):
    """'What does this category cover' is a real question, and the group prose is
    the only thing that answers it.

    Uses fetchall, not fetchone: a group whose overview is long enough to need
    splitting produces more than one such chunk, and a fetchone here would
    silently pass by matching whichever row SQLite happens to return first
    even if the substring only survives in a part that got dropped."""
    _ingest(conn)
    rows = conn.execute(
        "SELECT c.id, c.text FROM chunks c"
        " JOIN sections s ON s.id = c.section_id"
        " JOIN docs d ON d.id = s.doc_id"
        " WHERE d.doc_key = 'MASVS-STORAGE'"
        " AND c.id NOT IN (SELECT chunk_id FROM requirements)"
    ).fetchall()
    assert rows
    assert any("stored locally" in row["text"] for row in rows)


def test_the_section_anchor_keeps_the_hyphen(conn):
    """The anchor is half of a doc_key#anchor citation."""
    _ingest(conn)
    anchors = {r[0] for r in conn.execute("SELECT anchor FROM sections")}
    assert "masvs-storage" in anchors


def test_re_ingest_does_not_duplicate(conn):
    _ingest(conn)
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 2


def test_a_long_group_overview_splits_and_stays_inside_the_embedder_window(conn):
    """MASVS-PRIVACY's real v2.1.0 prose measures ~493 estimated tokens against
    the 512-token window -- within 4%, on a char/4 proxy a real BPE tokenizer
    can easily exceed on prose full of punctuation and URLs. This fixture's
    overview is built deliberately longer than that, as a worst case: five
    paragraphs totalling ~625 estimated tokens, so there is something to
    actually split rather than a value that merely happens to fit.
    """
    ingest_masvs(conn, LONG_OVERVIEW_FIXTURE, version="2.1.0", license="CC-BY-SA-4.0")
    overview_rows = conn.execute(
        "SELECT c.token_est FROM chunks c"
        " JOIN sections s ON s.id = c.section_id"
        " JOIN docs d ON d.id = s.doc_id"
        " WHERE d.doc_key = 'MASVS-PRIVACY'"
        " AND c.id NOT IN (SELECT chunk_id FROM requirements)"
    ).fetchall()
    assert len(overview_rows) > 1, "the long overview did not split"
    all_rows = conn.execute("SELECT token_est FROM chunks").fetchall()
    assert all(row["token_est"] <= EMBEDDER_MAX_TOKENS for row in all_rows), [
        row["token_est"] for row in all_rows
    ]


def test_every_overview_part_cites_through_the_group_anchor(conn):
    """The citation is doc_key#anchor. A future change to how the overview is
    split must not silently move it: every part still lives in the group's one
    section, and that section's anchor is still slugify(group_id) --
    MASVS-PRIVACY#masvs-privacy, not something split-specific."""
    ingest_masvs(conn, LONG_OVERVIEW_FIXTURE, version="2.1.0", license="CC-BY-SA-4.0")
    rows = conn.execute(
        "SELECT s.anchor, d.doc_key FROM chunks c"
        " JOIN sections s ON s.id = c.section_id"
        " JOIN docs d ON d.id = s.doc_id"
        " WHERE d.doc_key = 'MASVS-PRIVACY'"
        " AND c.id NOT IN (SELECT chunk_id FROM requirements)"
    ).fetchall()
    assert len(rows) > 1
    assert {row["doc_key"] for row in rows} == {"MASVS-PRIVACY"}
    assert {row["anchor"] for row in rows} == {"masvs-privacy"}


def test_a_source_with_no_controls_is_rejected(conn, tmp_path):
    """An upstream format change that parses is the failure ingest_cwe already
    guards against: a pack row exists, and nothing is in it."""
    empty = tmp_path / "empty.yaml"
    empty.write_text("metadata:\n  title: x\ngroups: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no controls"):
        ingest_masvs(conn, empty, version="2.1.0", license="CC-BY-SA-4.0")
