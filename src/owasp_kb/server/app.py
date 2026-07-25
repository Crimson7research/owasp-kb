"""MCP server entrypoint."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from owasp_kb.core.db import connect
from owasp_kb.core.kb import Kb
from owasp_kb.server.prompts import build_prompts
from owasp_kb.server.tools import build_tools

log = logging.getLogger(__name__)

DEFAULT_INDEX_PATH = Path(
    os.environ.get("OWASP_KB_INDEX", "/opt/owasp-kb/owasp-kb.sqlite")
)
SERVER_NAME = "owasp-kb"


def open_index(path: str | Path) -> Kb:
    """Open an index read-only and build the best available retriever.

    Always via core.db.connect: pragmas are per-connection, so a hand-rolled
    sqlite3.connect here would silently lose foreign_keys and anything added to
    the factory later. read_only=True also supplies the immutable=1 a shipped
    index requires, and refuses a WAL index that was never finalized.
    """
    index = Path(path)
    if not index.exists():
        raise FileNotFoundError(
            f"no index at {index}. Build one with 'owasp-kb-build --sources data --out "
            f"{index}', or set OWASP_KB_INDEX to an existing index."
        )

    try:
        conn = connect(index, load_vec=True, read_only=True)
    except RuntimeError:
        raise  # unfinalized WAL index: actionable, must not be swallowed
    except Exception as exc:  # noqa: BLE001 - degrade, never fail silently
        log.warning("sqlite-vec unavailable (%s); retrieval will be lexical only", exc)
        conn = connect(index, read_only=True)

    kb = Kb(conn)
    log.info("opened %s (mode=%s)", index, kb.info().retrieval_mode)
    return kb


def create_server(index_path: str | Path = DEFAULT_INDEX_PATH):
    """Build an MCP server with all tools and prompts registered."""
    from mcp.server import FastMCP

    kb = open_index(index_path)
    mcp = FastMCP(SERVER_NAME)
    for tool in build_tools(kb):
        mcp.tool()(tool)
    for prompt in build_prompts():
        mcp.prompt()(prompt)
    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OWASP KB MCP server")
    parser.add_argument("--index", default=str(DEFAULT_INDEX_PATH))
    args = parser.parse_args(argv)

    # stderr only: stdout is the MCP stdio transport, and anything written there
    # corrupts the protocol.
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s"
    )
    try:
        server = create_server(args.index)
    except (FileNotFoundError, RuntimeError) as exc:
        log.error("%s", exc)
        return 1
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
