"""Where the plugin's host-side state lives, resolved in exactly one place.

The same path is built independently by the .mcp.json wrapper, both PreToolUse
hooks and the assessment skills' prose. Every host-side subcommand resolves it
here instead, so adding a subcommand cannot introduce a fourth opinion about
where state lives.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# A session id as the harness produces it, plus a permissive tail for anything
# hand-made. Separators and dots are deliberately excluded: this value names a
# directory that `purge` deletes.
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def state_dir() -> Path:
    """The plugin's state root on the host.

    Mirrors `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb` from the .mcp.json
    wrapper. If that expression changes, this has to change with it.
    """
    base = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return Path(base) / "owasp-kb"


def sessions_dir() -> Path:
    return state_dir() / "sessions"


def validate_session_id(session: str) -> str:
    """`session`, if it names one directory and cannot escape the state tree.

    A session id reaches this CLI from an agent's shell command. `purge` removes a
    directory tree, so a value carrying a separator or `..` is refused here rather
    than sanitised further down, where a caller could skip the sanitising.
    """
    if not SESSION_ID.match(session):
        raise ValueError(
            f"{session!r} is not a session id. Expected letters, digits, hyphens "
            "and underscores only -- no path separators and no '..', because this "
            "names a directory that may be deleted."
        )
    return session


def session_dir(session: str) -> Path:
    """The directory for one session. Validates, rather than trusting the caller."""
    return sessions_dir() / validate_session_id(session)


def report_dir(session: str) -> Path:
    return session_dir(session) / "report"
