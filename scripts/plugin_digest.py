"""Digest of everything the plugin ships, recorded against its version.

The plugin cache is keyed on the version number. Ship a content change without
bumping it and the installed copy is not merely stale -- it is unreachable:
`/plugin` reports "already at the latest version", `/mcp` reports a successful
reconnect, and `/reload-plugins` reloads the old files. Three green statuses,
all true about the wrong artefact. Recovering needs a manual uninstall and
reinstall, and nothing indicates that it is necessary.

So the version is not decoration on a release, it is the delivery mechanism.
This records what the version was computed over, and the test refuses when the
two disagree -- which makes forgetting the bump a failing test rather than a
plugin that silently cannot be updated.

Run with --write after changing anything under plugins/, having bumped
``owasp_kb.__version__`` first.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

PLUGIN_DIR = Path("plugins/owasp-kb")
RECORD = PLUGIN_DIR / ".claude-plugin" / "content.sha256"


def digest(plugin_dir: Path = PLUGIN_DIR) -> str:
    """Hash every shipped file, path included.

    Paths are hashed alongside contents so a rename registers: an agent
    referenced by a name that moved is as broken as one whose body changed.
    Sorting keeps the result independent of filesystem order.
    """
    h = hashlib.sha256()
    for path in sorted(p for p in plugin_dir.rglob("*") if p.is_file()):
        if path == RECORD:
            continue
        h.update(path.relative_to(plugin_dir).as_posix().encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def recorded() -> tuple[str, str] | None:
    if not RECORD.is_file():
        return None
    version, _, value = RECORD.read_text().strip().partition(" ")
    return version, value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="record the current digest")
    args = parser.parse_args(argv)

    from owasp_kb import __version__

    value = digest()
    if args.write:
        RECORD.write_text(f"{__version__} {value}\n")
        print(f"recorded {__version__} {value}")
        return 0

    have = recorded()
    if have == (__version__, value):
        print(f"ok: {__version__} {value}")
        return 0
    print(f"stale: recorded {have}, computed ({__version__}, {value})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
