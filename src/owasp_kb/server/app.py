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

DEFAULT_INDEX_PATH = Path(os.environ.get("OWASP_KB_INDEX", "/opt/owasp-kb/owasp-kb.sqlite"))
SERVER_NAME = "owasp-kb"

# Container-first: the HTTP transports exist for the C7Agent sidecar deployment
# (c7-apps#3162), where the server is configured by its environment rather than
# by a command line. The env vars are argparse defaults, so an explicit flag
# wins -- the same precedence OWASP_KB_INDEX already follows.
TRANSPORTS = ("stdio", "sse", "streamable-http")


def _env_default(name: str, fallback: str) -> str:
    """Read an argparse default from the environment at parse time.

    Not a module-level constant: those freeze the value at import, so an
    embedder (or test) that sets the variable after importing this module would
    be silently ignored.
    """
    return os.environ.get(name, fallback)


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


def create_server(
    index_path: str | Path = DEFAULT_INDEX_PATH,
    host: str = "0.0.0.0",
    port: int = 8000,
):
    """Build an MCP server with all tools and prompts registered.

    host/port are FastMCP settings, read by the sse and streamable-http
    transports when they start uvicorn; the stdio transport ignores them.
    """
    from mcp.server import FastMCP

    kb = open_index(index_path)
    mcp = FastMCP(SERVER_NAME, host=host, port=port)
    for tool in build_tools(kb):
        mcp.tool()(tool)
    for prompt in build_prompts():
        mcp.prompt()(prompt)
    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OWASP KB MCP server")
    parser.add_argument("--index", default=str(DEFAULT_INDEX_PATH))
    # argparse does not apply `choices` to a default, and the env var becomes
    # one, so an invalid OWASP_KB_TRANSPORT would surface as an opaque
    # "Unknown transport" inside uvicorn startup. parser.error below turns it
    # into a CLI-level message that names the bad value, before any index is
    # opened or any port bound.
    parser.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default=_env_default("OWASP_KB_TRANSPORT", "stdio"),
        help="MCP transport to serve (default: stdio; env: OWASP_KB_TRANSPORT)",
    )
    parser.add_argument(
        "--host",
        default=_env_default("OWASP_KB_HOST", "0.0.0.0"),
        help="bind address for sse/streamable-http (default: 0.0.0.0; env: OWASP_KB_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(_env_default("OWASP_KB_PORT", "8000")),
        help="bind port for sse/streamable-http (default: 8000; env: OWASP_KB_PORT)",
    )
    args = parser.parse_args(argv)
    if args.transport not in TRANSPORTS:
        parser.error(
            f"invalid OWASP_KB_TRANSPORT value {args.transport!r}; expected one of "
            + ", ".join(TRANSPORTS)
        )

    # stderr only: stdout is the MCP stdio transport, and anything written there
    # corrupts the protocol.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s")
    try:
        server = create_server(args.index, host=args.host, port=args.port)
    except (FileNotFoundError, RuntimeError) as exc:
        log.error("%s", exc)
        return 1
    server.run(transport=args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
