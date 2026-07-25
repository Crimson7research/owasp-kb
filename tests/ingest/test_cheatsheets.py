import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.registry import get_pack
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets

FIXTURES = "tests/fixtures/cheatsheets"
SHA = "7d1c2d3daf632206e8f2c685214c699ff8f11938"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


def _ingest(conn, directory=FIXTURES):
    return ingest_cheatsheets(
        conn, directory, version="20260724", commit_sha=SHA, license="CC-BY-SA-4.0"
    )


def test_ingests_every_markdown_file(conn):
    assert _ingest(conn) == 3
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 3


def test_doc_key_is_filename_without_extension(conn):
    _ingest(conn)
    keys = {r[0] for r in conn.execute("SELECT doc_key FROM docs")}
    assert keys == {
        "Authentication_Cheat_Sheet",
        "Credential_Stuffing_Prevention_Cheat_Sheet",
        "Session_Management_Cheat_Sheet",
    }


def test_registers_pack_as_corpus_with_commit_sha(conn):
    _ingest(conn)
    pack = get_pack(conn, "cheatsheets")
    assert pack.type == "corpus"
    assert pack.commit_sha == SHA
    assert pack.version == "20260724"


def test_title_comes_from_the_h1(conn):
    _ingest(conn)
    title = conn.execute(
        "SELECT title FROM docs WHERE doc_key = 'Authentication_Cheat_Sheet'"
    ).fetchone()[0]
    assert title == "Authentication Cheat Sheet"


def test_sections_get_anchors(conn):
    _ingest(conn)
    anchors = {r[0] for r in conn.execute("SELECT anchor FROM sections")}
    assert "password-storage" in anchors
    assert "protecting-against-automated-attacks" in anchors


def test_heading_path_is_rooted_at_the_title(conn):
    _ingest(conn)
    path = conn.execute(
        "SELECT heading_path FROM sections WHERE anchor = 'password-storage'"
    ).fetchone()[0]
    assert path == "Authentication Cheat Sheet > Password Storage"


def test_content_is_full_text_searchable(conn):
    _ingest(conn)
    hits = conn.execute(
        "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH 'credential stuffing'"
    ).fetchall()
    # Two fixtures mention the phrase: the Authentication sheet and the
    # Credential Stuffing sheet that IndexASVS_sample.md maps V6.2 to.
    assert len(hits) == 2


def test_source_url_points_at_the_pinned_commit(conn):
    """A citation must resolve to the exact text indexed, not a moving branch."""
    _ingest(conn)
    url = conn.execute(
        "SELECT source_url FROM docs WHERE doc_key = 'Authentication_Cheat_Sheet'"
    ).fetchone()[0]
    assert SHA in url
    assert "Authentication_Cheat_Sheet.md" in url
    assert "/blob/main/" not in url and "/blob/master/" not in url


def test_source_path_is_recorded(conn):
    _ingest(conn)
    path = conn.execute(
        "SELECT source_path FROM docs WHERE doc_key = 'Session_Management_Cheat_Sheet'"
    ).fetchone()[0]
    assert path == "cheatsheets/Session_Management_Cheat_Sheet.md"


def test_every_section_has_at_least_one_chunk(conn):
    _ingest(conn)
    empty = conn.execute(
        "SELECT s.anchor FROM sections s LEFT JOIN chunks c ON c.section_id = s.id"
        " GROUP BY s.id HAVING COUNT(c.id) = 0"
    ).fetchall()
    assert empty == []


def test_reingest_is_idempotent(conn):
    _ingest(conn)
    before = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    _ingest(conn)
    assert conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == before


def test_reingest_leaves_no_stale_fts_rows(conn):
    _ingest(conn)
    _ingest(conn)
    fts = conn.execute("SELECT COUNT(*) FROM chunks_fts").fetchone()[0]
    chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    assert fts == chunks
    conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('integrity-check')")


def test_a_document_without_an_h1_falls_back_to_its_filename(conn, tmp_path):
    directory = tmp_path / "cs"
    directory.mkdir()
    (directory / "No_Title_Cheat_Sheet.md").write_text("## Only A Section\n\nbody text\n")
    assert _ingest(conn, directory) == 1
    title = conn.execute("SELECT title FROM docs").fetchone()[0]
    assert title == "No Title Cheat Sheet"


def test_an_empty_directory_raises_rather_than_silently_doing_nothing(conn, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        _ingest(conn, empty)


def test_repeated_headings_produce_distinct_sections(conn, tmp_path):
    """9 of the 120 real cheat sheets repeat headings; sections carries
    UNIQUE(doc_id, anchor), so a collision would merge unrelated content and
    mis-cite it."""
    directory = tmp_path / "cs"
    directory.mkdir()
    (directory / "Dup_Cheat_Sheet.md").write_text(
        "# Dup Cheat Sheet\n\n## X-Frame-Options\n\nxfo\n\n### Limitations\n\nxfo limits\n\n"
        "## CSP\n\ncsp\n\n### Limitations\n\ncsp limits\n"
    )
    _ingest(conn, directory)
    rows = dict(
        conn.execute("SELECT anchor, heading_path FROM sections WHERE anchor LIKE 'limitations%'")
    )
    assert set(rows) == {"limitations", "limitations-1"}
    assert rows["limitations"].endswith("X-Frame-Options > Limitations")
    assert rows["limitations-1"].endswith("CSP > Limitations")
