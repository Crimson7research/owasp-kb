import sqlite3
from unittest.mock import patch

import pytest

from owasp_kb.core.db import connect, finalize_for_readonly
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.server.app import (
    DEFAULT_INDEX_PATH,
    SERVER_NAME,
    create_server,
    main,
    open_index,
)


@pytest.fixture
def index(tmp_path):
    path = tmp_path / "kb.sqlite"
    conn = connect(path)
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


# --- transport selection ----------------------------------------------------
#
# main() runs a server and returns when it stops; tests patch create_server so
# the fake server records the run() call instead of binding anything. The
# assertion is on what run() received, not on what the parser returned: a
# transport value that stops at the parser and never reaches server.run is the
# regression these tests exist for.
#
# An env-var override (OWASP_KB_TRANSPORT) is checked separately from argparse
# defaults, because argparse never applies `choices` to a default -- a typo in
# the environment would otherwise surface as an opaque FastMCP
# "Unknown transport" error deep in uvicorn startup instead of an actionable
# CLI message.


class _FakeServer:
    def __init__(self):
        self.run_calls = []

    def run(self, transport=None):
        self.run_calls.append(transport)


def test_main_defaults_to_stdio(index, monkeypatch):
    fake = _FakeServer()
    monkeypatch.delenv("OWASP_KB_TRANSPORT", raising=False)
    with patch("owasp_kb.server.app.create_server", return_value=fake):
        assert main(["--index", str(index)]) == 0
    assert fake.run_calls == ["stdio"]


def test_main_rejects_an_unknown_transport(index):
    with pytest.raises(SystemExit) as excinfo:
        main(["--index", str(index), "--transport", "websocket"])
    assert excinfo.value.code != 0


def test_main_accepts_each_http_transport(index):
    for transport in ("sse", "streamable-http"):
        fake = _FakeServer()
        with patch("owasp_kb.server.app.create_server", return_value=fake):
            assert main(["--index", str(index), "--transport", transport]) == 0
        assert fake.run_calls == [transport]


def test_main_reads_the_transport_from_the_environment(index, monkeypatch):
    fake = _FakeServer()
    monkeypatch.setenv("OWASP_KB_TRANSPORT", "streamable-http")
    with patch("owasp_kb.server.app.create_server", return_value=fake):
        assert main(["--index", str(index)]) == 0
    assert fake.run_calls == ["streamable-http"]


def test_main_rejects_an_unknown_transport_from_the_environment(index, monkeypatch, capsys):
    """argparse never applies choices to a default, and the environment becomes
    the default -- so OWASP_KB_TRANSPORT=gopher would reach FastMCP and die as
    an opaque "Unknown transport" inside uvicorn startup if main() trusted it."""
    monkeypatch.setenv("OWASP_KB_TRANSPORT", "gopher")
    with pytest.raises(SystemExit) as excinfo:
        main(["--index", str(index)])
    assert excinfo.value.code != 0
    assert "gopher" in capsys.readouterr().err


# --- host/port for the HTTP transports ---------------------------------------
#
# FastMCP reads host/port from server.settings, not from run(), so main() has
# to hand them over when the server is built. The fake records its settings the
# same way create_server constructs the real one.


class _FakeSettings:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class _FakeServerWithSettings(_FakeServer):
    def __init__(self, host, port):
        super().__init__()
        self.settings = _FakeSettings(host, port)


def test_main_defaults_host_and_port(index, monkeypatch):
    for var in ("OWASP_KB_HOST", "OWASP_KB_PORT"):
        monkeypatch.delenv(var, raising=False)
    fake = _FakeServerWithSettings(None, None)

    def fake_create_server(index_path, host=None, port=None):
        fake.settings.host, fake.settings.port = host, port
        return fake

    with patch("owasp_kb.server.app.create_server", side_effect=fake_create_server):
        assert main(["--index", str(index), "--transport", "sse"]) == 0
    assert (fake.settings.host, fake.settings.port) == ("0.0.0.0", 8000)


def test_main_passes_host_and_port_arguments_to_the_server(index):
    fake = _FakeServerWithSettings(None, None)

    def fake_create_server(index_path, host=None, port=None):
        fake.settings.host, fake.settings.port = host, port
        return fake

    with patch("owasp_kb.server.app.create_server", side_effect=fake_create_server):
        argv = [
            "--index",
            str(index),
            "--transport",
            "sse",
            "--host",
            "127.0.0.1",
            "--port",
            "9001",
        ]
        assert main(argv) == 0
    assert (fake.settings.host, fake.settings.port) == ("127.0.0.1", 9001)


def test_main_reads_host_and_port_from_the_environment(index, monkeypatch):
    monkeypatch.setenv("OWASP_KB_HOST", "10.0.0.5")
    monkeypatch.setenv("OWASP_KB_PORT", "8123")
    fake = _FakeServerWithSettings(None, None)

    def fake_create_server(index_path, host=None, port=None):
        fake.settings.host, fake.settings.port = host, port
        return fake

    with patch("owasp_kb.server.app.create_server", side_effect=fake_create_server):
        assert main(["--index", str(index), "--transport", "streamable-http"]) == 0
    assert (fake.settings.host, fake.settings.port) == ("10.0.0.5", 8123)


def test_main_a_cli_flag_overrides_the_environment(index, monkeypatch):
    monkeypatch.setenv("OWASP_KB_HOST", "10.0.0.5")
    monkeypatch.setenv("OWASP_KB_PORT", "8123")
    fake = _FakeServerWithSettings(None, None)

    def fake_create_server(index_path, host=None, port=None):
        fake.settings.host, fake.settings.port = host, port
        return fake

    with patch("owasp_kb.server.app.create_server", side_effect=fake_create_server):
        assert main(["--index", str(index), "--host", "192.168.0.2", "--port", "9999"]) == 0
    assert (fake.settings.host, fake.settings.port) == ("192.168.0.2", 9999)
    assert fake.run_calls == ["stdio"]
