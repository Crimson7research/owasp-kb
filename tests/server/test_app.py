import sqlite3

import pytest

from owasp_kb.core.db import connect, finalize_for_readonly
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.server.app import DEFAULT_INDEX_PATH, SERVER_NAME, create_server, open_index


@pytest.fixture
def index(tmp_path):
    path = tmp_path / "kb.sqlite"
    conn = connect(path)
    create_schema(conn)
    ingest_asvs(conn, "tests/fixtures/asvs_sample.flat.json",
                version="5.0.0", license="CC-BY-SA-4.0")
    ingest_cheatsheets(conn, "tests/fixtures/cheatsheets", version="20260724",
                       commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
                       license="CC-BY-SA-4.0")
    finalize_for_readonly(conn)
    conn.close()
    return path


def test_default_index_path_is_inside_the_image():
    assert str(DEFAULT_INDEX_PATH) == "/opt/owasp-kb/owasp-kb.sqlite"


def test_missing_index_raises_an_actionable_error(tmp_path):
    with pytest.raises(FileNotFoundError) as excinfo:
        open_index(tmp_path / "absent.sqlite")
    assert "owasp-kb-build" in str(excinfo.value) or "build" in str(excinfo.value)


def test_open_index_reports_lexical_without_vectors(index):
    assert open_index(index).info().retrieval_mode == "lexical"


def test_open_index_is_read_only(index):
    """A server bug must not be able to corrupt a shipped index."""
    kb = open_index(index)
    with pytest.raises(sqlite3.OperationalError):
        kb._conn.execute("INSERT INTO packs(name, type, version) VALUES ('x','corpus','1')")


def test_open_index_refuses_an_unfinalized_wal_index(tmp_path):
    """WAL cannot be served from the image's non-writable directory, and
    immutable=1 on a changing file can return silently wrong results."""
    path = tmp_path / "wal.sqlite"
    conn = connect(path)
    create_schema(conn)
    conn.commit()
    conn.close()  # deliberately not finalized
    with pytest.raises(RuntimeError, match="WAL"):
        open_index(path)


def test_create_server_registers_tools_and_prompts(index):
    server = create_server(index)
    assert server is not None
    assert server.name == SERVER_NAME


def test_create_server_on_a_missing_index_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        create_server(tmp_path / "absent.sqlite")
