from pathlib import Path

import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.integrity import EMBEDDER_MAX_TOKENS
from owasp_kb.core.registry import get_pack
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.aisvs import ingest_aisvs, parse_chapter

FIXTURE_DIR = Path("tests/fixtures/aisvs")

# Written by fetch.fetch_release_pack per sources.lock.yml's aisvs.extra_paths --
# not present in this checkout. The realdata tests below skip without it.
REAL_DIR = Path("data/aisvs")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


def _ingest(conn, directory=FIXTURE_DIR):
    return ingest_aisvs(conn, directory, version="1.01", license="CC-BY-SA-4.0")


def _write_chapter(directory: Path, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "0x10-C02-Input-Validation.md"
    path.write_text(body, encoding="utf-8")
    return path


_HEADER = "# C2 Input Validation\n\n## C2.1 Prompt Injection Defenses\n\n"
_TABLE_HEAD = "| # | Description | Level |\n| :--: | --- | :---: |\n"


def test_ingests_every_live_requirement(conn):
    """The fixture holds six rows; 10.2.6 is a tombstone, so five are live."""
    assert _ingest(conn) == 5
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 5


def test_registers_pack_as_checklist(conn):
    _ingest(conn)
    pack = get_pack(conn, "aisvs")
    assert pack.type == "checklist"
    assert pack.version == "1.01"
    assert pack.license == "CC-BY-SA-4.0"
    assert pack.source_url == "https://github.com/OWASP/AISVS"


def test_ids_carry_the_upstream_c_prefix(conn):
    """Upstream cites v1.01-C10.2.2. A bare 10.2.2 would sit beside ASVS's V10.2.2
    in the links table, whose ids carry no pack, and _id_candidates would roll it
    up to chapter "10" -- an id nothing distinguishes from a typo."""
    _ingest(conn)
    row = conn.execute(
        "SELECT chapter_id, chapter_name, section_id, section_name, level FROM requirements"
        " WHERE req_id = 'C10.2.1'"
    ).fetchone()
    assert row["chapter_id"] == "C10"
    assert row["chapter_name"] == "Model Context Protocol (MCP) Security"
    assert row["section_id"] == "C10.2"
    assert row["section_name"] == "Authentication & Authorization"
    assert row["level"] == "1"


def test_requirement_text_drops_the_markdown_emphasis(conn):
    _ingest(conn)
    text = conn.execute("SELECT text FROM requirements WHERE req_id = 'C2.2.1'").fetchone()[0]
    assert text.startswith("Verify that inputs are screened")
    assert "**" not in text
    assert "`allow-list`" in text


def test_a_removed_requirement_is_not_ingested(conn):
    """1.01 keeps 10.2.6 as a numbered tombstone row with no level. It is not a
    requirement anyone can be assessed against."""
    _ingest(conn)
    ids = {r[0] for r in conn.execute("SELECT req_id FROM requirements")}
    assert "C10.2.6" not in ids


def test_ordinals_follow_chapter_then_document_order(conn):
    """10.2.10 after 10.2.1: document order, not a lexical sort of the ids."""
    _ingest(conn)
    order = [r[0] for r in conn.execute("SELECT req_id FROM requirements ORDER BY ord")]
    assert order == ["C2.1.1", "C2.1.2", "C2.2.1", "C10.2.1", "C10.2.10"]


def test_levels_are_kept_per_requirement(conn):
    _ingest(conn)
    levels = dict(conn.execute("SELECT req_id, level FROM requirements"))
    assert levels == {
        "C2.1.1": "1",
        "C2.1.2": "2",
        "C2.2.1": "3",
        "C10.2.1": "1",
        "C10.2.10": "2",
    }


def test_one_doc_per_chapter_keyed_on_the_chapter_id(conn):
    _ingest(conn)
    docs = dict(conn.execute("SELECT doc_key, title FROM docs ORDER BY id"))
    assert docs == {
        "C2": "C2: Input Validation",
        "C10": "C10: Model Context Protocol (MCP) Security",
    }


def test_the_control_objective_is_retrievable_and_has_no_requirement(conn):
    """'What does this chapter cover' is answered only by the objective prose."""
    _ingest(conn)
    rows = conn.execute(
        "SELECT c.text, s.anchor FROM chunks c"
        " JOIN sections s ON s.id = c.section_id"
        " JOIN docs d ON d.id = s.doc_id"
        " WHERE d.doc_key = 'C2' AND c.id NOT IN (SELECT chunk_id FROM requirements)"
    ).fetchall()
    objective = [r for r in rows if r["anchor"] == "control-objective"]
    assert objective
    assert "first-line defense against prompt injection" in objective[0]["text"]


def test_section_prose_is_retrievable_under_the_section_anchor(conn):
    _ingest(conn)
    rows = conn.execute(
        "SELECT c.text FROM chunks c JOIN sections s ON s.id = c.section_id"
        " WHERE s.anchor = 'c21' AND c.id NOT IN (SELECT chunk_id FROM requirements)"
    ).fetchall()
    assert any("instruction hierarchy enforcement" in r["text"] for r in rows)


def test_the_references_section_is_not_indexed(conn):
    """A link list is not guidance text. Its cheat sheet links become edges."""
    _ingest(conn)
    anchors = {r[0] for r in conn.execute("SELECT anchor FROM sections")}
    assert "references" not in anchors


def test_each_requirement_chunk_names_id_and_level(conn):
    _ingest(conn)
    text = conn.execute(
        "SELECT c.text FROM chunks c JOIN requirements r ON r.chunk_id = c.id"
        " WHERE r.req_id = 'C10.2.1'"
    ).fetchone()[0]
    assert text.startswith("Model Context Protocol (MCP) Security > Authentication & Authorization")
    assert "C10.2.1 (L1): Verify that MCP servers validate access tokens" in text


def test_re_ingest_does_not_duplicate(conn):
    _ingest(conn)
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 2


def test_a_directory_with_no_chapters_is_rejected(conn, tmp_path):
    """A pack row over an empty pack reads as a pack that exists and is empty."""
    with pytest.raises(ValueError, match="no AISVS chapter files"):
        _ingest(conn, tmp_path)


def test_a_chapter_with_no_requirements_is_rejected(conn, tmp_path):
    _write_chapter(tmp_path, _HEADER + "Prose only.\n")
    with pytest.raises(ValueError, match="no requirement rows"):
        _ingest(conn, tmp_path)


def test_an_unlevelled_row_that_is_not_a_tombstone_is_rejected(conn, tmp_path):
    """Only 'Requirement removed.' may lack a level. Anything else without one is
    an upstream format change, and guessing a level would misstate the standard."""
    _write_chapter(tmp_path, _HEADER + _TABLE_HEAD + "| **2.1.1** | **Verify that** x. | |\n")
    with pytest.raises(ValueError, match="2.1.1.*no level"):
        _ingest(conn, tmp_path)


def test_a_row_outside_its_section_is_rejected(conn, tmp_path):
    """3.1.1 under C2.1 means the heading or the id moved; either breaks citations."""
    _write_chapter(tmp_path, _HEADER + _TABLE_HEAD + "| **3.1.1** | **Verify that** x. | 1 |\n")
    with pytest.raises(ValueError, match="3.1.1.*C2.1"):
        _ingest(conn, tmp_path)


def test_a_row_before_any_section_is_rejected(conn, tmp_path):
    _write_chapter(tmp_path, "# C2 Input Validation\n\n" + _TABLE_HEAD + "| **2.1.1** | x. | 1 |\n")
    with pytest.raises(ValueError, match="before any section heading"):
        _ingest(conn, tmp_path)


def test_parse_chapter_reads_the_chapter_heading():
    chapter = parse_chapter(
        _HEADER + _TABLE_HEAD + "| **2.1.1** | **Verify that** x. | 1 |\n", "fixture.md"
    )
    assert chapter.chapter_id == "C2"
    assert chapter.name == "Input Validation"
    assert [s.section_id for s in chapter.sections] == ["C2.1"]


def test_parse_chapter_rejects_a_file_without_a_chapter_heading():
    with pytest.raises(ValueError, match="no '# C<n>' chapter heading"):
        parse_chapter("## C2.1 Section\n", "fixture.md")


# --- against the pinned release, not the fixture ----------------------------
#
# The figures below are measured on tag v1.01, folder 1.01/en/: 214 table rows,
# one of them the 10.2.6 tombstone, so 213 live requirements -- 57 at L1, 110 at
# L2, 46 at L3. build.EXPECTED_REQUIREMENTS gates the build on 213 already; this
# fails earlier and names the shape that moved.


@pytest.mark.realdata
def test_the_real_release_matches_the_shape_the_build_expects(conn):
    if not REAL_DIR.exists():
        pytest.skip(f"no AISVS chapters at {REAL_DIR}; run the fetch step first")
    assert _ingest(conn, REAL_DIR) == 213
    by_level = dict(conn.execute("SELECT level, COUNT(*) FROM requirements GROUP BY level"))
    assert by_level == {"1": 57, "2": 110, "3": 46}
    chapters = [r[0] for r in conn.execute("SELECT doc_key FROM docs ORDER BY id")]
    assert chapters == [f"C{n}" for n in range(1, 13)]


@pytest.mark.realdata
def test_no_chunk_from_the_real_release_exceeds_the_embedder_window(conn):
    if not REAL_DIR.exists():
        pytest.skip(f"no AISVS chapters at {REAL_DIR}; run the fetch step first")
    _ingest(conn, REAL_DIR)
    biggest = conn.execute("SELECT MAX(token_est) FROM chunks").fetchone()[0]
    assert biggest <= EMBEDDER_MAX_TOKENS, f"largest chunk {biggest} exceeds the embedder window"
