#!/usr/bin/env python3
"""Write the release version into the one literal that carries it.

`__version__` in `src/owasp_kb/__init__.py` versions the Python package and the image
built from it, and `kb_info` reports it as `server_version`. It was bumped by hand
before a tag was cut, and at `v0.17.1` the bump was skipped: the image published for
that tag reports `0.17.0`, and nothing failed.

The cost is not a wrong number in a response. `kb_info`'s own description tells a caller
to compare `server_version` against the plugin version it expects, because a reconnect
reports success whether or not the image behind it is current. That comparison is the
only staleness detector this project has, and a skipped bump makes a stale server
indistinguishable from a fresh one. It cost exactly that once: a session read `0.17.0`
from a server pinned at `v0.17.2` and could not tell which of the two failures it was
looking at.

So the tag writes it. `release.yml` runs this before the image is built, because a
version written afterwards fixes the repository and not the artefact -- which is the
`v0.17.1` shape again, one release later. The same edit reaches the default branch
through the release pull request.

The format check is not a monotonicity check. Nothing here refuses a version that goes
backwards or repeats one already published; it refuses a string that is not a version at
all, so a malformed tag cannot become a published build's identity.

See ADR 0016.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

INIT = Path("src/owasp_kb/__init__.py")

# Anchored to its own line, because the module docstring discusses `__version__` and an
# unanchored pattern would rewrite prose alongside the assignment. One pattern, used for
# both the search in `current` and the substitution in `rewrite`: two equivalent regexes
# encoding the same line shape can be edited to disagree about what the literal is.
LITERAL = re.compile(r'^__version__ = "([^"]*)"$', re.MULTILINE)

# Three dot-separated integers, with or without the `v` a git tag carries. Deliberately
# narrower than PEP 440: every release here has been X.Y.Z, and the image tag scheme has
# never carried a pre-release form, so accepting `v1.0.0rc1` would put a shape nothing
# downstream handles into a published tag.
TAG = re.compile(r"^v?(\d+\.\d+\.\d+)$")

# The bare form `parse_tag` produces. Checked again here because `pin_image.py`'s
# equivalents re-validate rather than trusting their caller, and the failure mode is a
# corrupted module rather than an error.
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def parse_tag(tag: str) -> str:
    """The bare version in `tag`, or exit."""
    match = TAG.match(tag.strip())
    if not match:
        raise SystemExit(
            f"error: {tag!r} is not a release tag of the form vX.Y.Z.\n"
            "This version is baked into a published image and reported by kb_info as "
            "that build's identity, so a malformed tag must fail before the build."
        )
    return match.group(1)


def current(text: str) -> str:
    """The version `text` currently declares."""
    match = LITERAL.search(text)
    if not match:
        raise SystemExit(
            f"error: no __version__ assignment found in {INIT}. Either the module "
            "changed shape or the literal was removed; this script edits that line "
            "and has nothing to edit."
        )
    return match.group(1)


def rewrite(text: str, version: str) -> str:
    """`text` with its version literal replaced by `version`."""
    current(text)  # raises if there is no literal to replace
    if not VERSION.match(version):
        raise SystemExit(
            f"error: {version!r} is not a version of the form X.Y.Z. This is written "
            "into a module that gets imported, so a malformed value corrupts the "
            "package rather than failing a check."
        )
    # A lambda rather than a replacement string: `re.sub` interprets backslashes in a
    # replacement, and the failure would be a corrupted module rather than an error.
    return LITERAL.sub(lambda _: f'__version__ = "{version}"', text, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="set_version.py", description=__doc__)
    parser.add_argument("--tag", help="the release tag to take the version from")
    parser.add_argument("--write", action="store_true", help="write the change to disk")
    parser.add_argument("--show", action="store_true", help="print the current version and exit")
    args = parser.parse_args(argv)

    text = INIT.read_text()

    if args.show:
        print(current(text))
        return 0

    if not args.tag:
        parser.error("--tag is required unless --show is given")

    version = parse_tag(args.tag)
    updated = rewrite(text, version)

    if not args.write:
        print(updated, end="")
        return 0

    if updated == text:
        print(f"{INIT} already declares {version}")
    else:
        INIT.write_text(updated)
        print(f"set {INIT} to {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
