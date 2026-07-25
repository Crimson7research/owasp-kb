"""SQLite connection factory."""

from __future__ import annotations

import sqlite3
import urllib.parse
from pathlib import Path

SQLITE_HEADER_WRITE_VERSION_OFFSET = 18
WAL_WRITE_VERSION = 2


def is_wal_index(path: str | Path) -> bool:
    """Whether this file's SQLite header says it is in WAL mode.

    Byte 18 of the header is the file-format write version: 1 for a rollback
    journal, 2 for WAL. This reads the file directly rather than asking SQLite,
    because ``PRAGMA journal_mode`` reports ``delete`` through an
    ``immutable=1`` connection no matter what the header actually says --
    immutable tells SQLite to ignore the journal entirely, so the pragma cannot
    detect this.
    """
    try:
        with Path(path).open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return False
    if len(header) < SQLITE_HEADER_WRITE_VERSION_OFFSET + 1:
        return False
    return header[SQLITE_HEADER_WRITE_VERSION_OFFSET] == WAL_WRITE_VERSION


def connect(
    path: str | Path, *, load_vec: bool = False, read_only: bool = False
) -> sqlite3.Connection:
    """Open a connection with the pragmas this project relies on.

    ``load_vec`` loads the sqlite-vec extension, raising if it is unavailable so
    callers decide to degrade rather than fail silently.

    ``read_only`` opens the index for serving: ``mode=ro`` plus ``immutable=1``,
    and no journal-mode change. This is the only supported way to open a shipped
    index — see finalize_for_readonly on why.

    All pragmas are per-connection, so every consumer must come through this
    factory rather than calling sqlite3.connect directly.
    """
    if read_only:
        index = Path(path)
        if is_wal_index(index):
            raise RuntimeError(
                f"{index} is still in WAL mode and cannot be served safely. "
                "immutable=1 skips locking and change detection, so SQLite may "
                "return silently incorrect results for a file that is still being "
                "written. Call finalize_for_readonly() at the end of the build "
                "before serving this index."
            )
        # quote() matters: an unencoded '?' or '#' in the path makes SQLite open a
        # DIFFERENT database without erroring, which is a silent-wrong-data bug.
        conn = sqlite3.connect(
            "file:" + urllib.parse.quote(str(index)) + "?mode=ro&immutable=1", uri=True
        )
        conn.row_factory = sqlite3.Row
    else:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")

    if load_vec:
        import sqlite_vec

        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
    return conn


def finalize_for_readonly(conn: sqlite3.Connection) -> None:
    """Prepare a freshly built index to be shipped on read-only media.

    WAL mode is recorded in the database header and persists. A WAL database in a
    directory the process cannot write fails to open with
    ``OperationalError: attempt to write a readonly database``, because SQLite
    needs to create the -wal and -shm sidecars. The image bakes the index into a
    root-owned /opt/owasp-kb and the server runs as an unprivileged user, so the
    build must check the WAL back into the main file and downgrade the journal
    mode before packaging.
    """
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.commit()


def vec_available(conn: sqlite3.Connection) -> bool:
    """True when the sqlite-vec extension is loaded in this connection."""
    try:
        conn.execute("SELECT vec_version()")
        return True
    except sqlite3.OperationalError:
        return False
