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
