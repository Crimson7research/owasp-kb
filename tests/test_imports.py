def test_mcp_sdk_exposes_fastmcp():
    from mcp.server import FastMCP

    assert hasattr(FastMCP, "tool")
    assert hasattr(FastMCP, "prompt")
    assert hasattr(FastMCP, "run")


def test_fastmcp_run_accepts_stdio_transport():
    import inspect

    from mcp.server import FastMCP

    params = inspect.signature(FastMCP.run).parameters
    assert "transport" in params
    assert params["transport"].default == "stdio"


def test_fastmcp_run_accepts_the_http_transports():
    """server/app.py passes --transport straight through to FastMCP.run, so the
    two HTTP choices must exist in the installed mcp -- an upgrade that drops
    one would surface as an opaque ValueError inside uvicorn startup."""
    import typing

    from mcp.server import FastMCP

    # get_type_hints, not signature().parameters: mcp uses PEP 563 annotations,
    # so the raw annotation is the literal string "Literal['stdio', ...]".
    annotation = typing.get_type_hints(FastMCP.run)["transport"]
    values = set()
    for arg in typing.get_args(annotation):
        values.update(typing.get_args(arg) or [arg])
    assert {"stdio", "sse", "streamable-http"} <= values


def test_sqlite_has_fts5_and_extension_loading():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    assert hasattr(conn, "enable_load_extension")
    conn.execute("CREATE VIRTUAL TABLE t USING fts5(x)")


def test_sqlite_vec_loads():
    import sqlite3

    import sqlite_vec

    conn = sqlite3.connect(":memory:")
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)
    (version,) = conn.execute("SELECT vec_version()").fetchone()
    assert version
