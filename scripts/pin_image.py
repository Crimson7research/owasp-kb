#!/usr/bin/env python3
"""Point the plugin's MCP config at a published image, by digest.

`.mcp.json` used to default to `owasp-kb:full`. An unqualified name resolves to
`docker.io/library/owasp-kb`, so docker checked the local store and then failed
against Docker Hub -- the plugin worked only for someone who had run `make build`.

A fully-qualified tag would reach the registry and still lose to any local image of
that name, because `--pull=missing` is docker's default and `docker tag` is
unprivileged. `--pull=always` would fix that by putting a registry round-trip on
every server start, which is the wrong trade for a tool whose stated value is
working inside a network that is deliberately locked down.

A digest cannot be shadowed: a local cache hit on it *is* the published bytes, and
it is pulled once rather than checked every session. The digest is only knowable
after the push, so this runs at release time and its output reaches the default
branch through a pull request. The marketplace is read from the default branch, so
that merge is the delivery.

Alongside the digest this records the pack versions the lock declared *at the moment
the image was built*, because that is the only claim the shipped image can be held
to. The lock moves ahead of the image on every content refresh and stays ahead until
the next release ships -- see ADR 0015.

See ADR 0014.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

MCP_CONFIG = Path("plugins/owasp-kb/.mcp.json")
LOCK = Path("sources.lock.yml")
# Written beside the config it describes rather than at the repository root: the two
# are one fact -- this digest holds these packs -- and a release pull request that
# carried one without the other would ship a claim about the wrong image.
PINNED_PACKS = Path("plugins/owasp-kb/pinned-packs.json")

INIT = Path("src/owasp_kb/__init__.py")

# Duplicated deliberately from scripts/set_version.py rather than shared. A module under
# src/owasp_kb/ would be importable here, but not from set_version.py: that runs before
# release.yml's Install step, so the package is not installed and src/ is not on the path
# when the version is written. `test_both_scripts_read_the_same_version_literal` guards
# the duplication instead.
VERSION_LITERAL = re.compile(r'^__version__ = "([^"]*)"$', re.MULTILINE)

# What kb_info reports and what doctor compares against: the same narrow form the
# release tag is held to.
VERSION = re.compile(r"^\d+\.\d+\.\d+$")

# The whole ${OWASP_KB_IMAGE:-...} default, whatever form it currently holds. The
# override itself is preserved: it is how a dev points at a local build and how the
# lite variant is selected.
DEFAULT_IMAGE = re.compile(r"\$\{OWASP_KB_IMAGE:-([^}]+)\}")

# Anchored, and the registry host is part of it: `crimson7research/owasp-kb@sha256:...`
# without a host resolves to Docker Hub, which would look pinned and pull nothing.
# Lowercase hex only -- docker rejects a mixed-case digest, so accepting one here
# would move the failure from the release to a dev's first container start.
PINNED = re.compile(r"^ghcr\.io/[a-z0-9][a-z0-9._-]*/owasp-kb@sha256:[0-9a-f]{64}$")


def current(text: str) -> str:
    """The image reference the config currently defaults to."""
    match = DEFAULT_IMAGE.search(text)
    if not match:
        raise SystemExit(
            "error: no ${OWASP_KB_IMAGE:-...} default found. Either the config "
            "changed shape or the override was removed; this script edits that "
            "default and has nothing to edit."
        )
    return match.group(1)


def version_of(text: str) -> str:
    """The version `src/owasp_kb/__init__.py` declares."""
    match = VERSION_LITERAL.search(text)
    if not match:
        raise SystemExit(
            f"error: no __version__ assignment found in {INIT}, so the record cannot "
            "name the version this image reports."
        )
    return match.group(1)


def rewrite(text: str, image: str) -> str:
    """`text` with its default image reference replaced by `image`."""
    if not PINNED.match(image):
        raise SystemExit(
            f"error: {image!r} is not a digest-pinned GHCR reference.\n"
            "A tag can be reassigned after the plugin ships and a bare name "
            "resolves to Docker Hub -- both leave a config that looks pinned and "
            "is not. Expected ghcr.io/<owner>/owasp-kb@sha256:<64 lowercase hex>."
        )
    # A lambda rather than a replacement string: a digest carries no backslashes
    # today, but re.sub would interpret one if it ever did, and the failure would be
    # a corrupted config rather than an error.
    result = DEFAULT_IMAGE.sub(lambda _: "${OWASP_KB_IMAGE:-" + image + "}", text, count=1)
    # The harness reads this file as JSON. A rewrite that breaks it surfaces as a
    # plugin that fails to load, with nothing pointing back here.
    json.loads(result)
    return result


def record(image: str, lock_text: str, version: str) -> str:
    """The provenance record for `image`: the digest, and the pack versions the lock
    declared when it was built.

    `scripts/verify_pin.sh` reads this rather than the working tree's lock. Reading
    the lock directly asserted that the shipped image is current with whatever the
    branch declares, which no lock-bump commit can satisfy: the image for those
    versions does not exist until the release that follows the merge. That check
    failed the first content-refresh pull request it ever saw, and would have turned
    master red on merge. See ADR 0015.

    The version is here so `doctor` can tell a stale server from a fresh one. At
    v0.17.1 the hand bump was skipped and the published image reported the previous
    release's number, which made that comparison impossible -- see ADR 0016.
    """
    if not PINNED.match(image):
        raise SystemExit(f"error: {image!r} is not a digest-pinned GHCR reference.")
    if not VERSION.match(version):
        raise SystemExit(
            f"error: {version!r} is not a version of the form X.Y.Z.\n"
            "doctor holds the running server to this value, and a record naming "
            "something no server can report makes every check fail."
        )
    packs = yaml.safe_load(lock_text)["packs"]
    document = {
        "image": image,
        "packs": {name: str(packs[name]["version"]) for name in sorted(packs)},
        "server_version": version,
    }
    return json.dumps(document, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pin_image.py", description=__doc__)
    parser.add_argument("--image", help="the digest-pinned reference to pin to")
    parser.add_argument("--write", action="store_true", help="write the change to disk")
    parser.add_argument("--show", action="store_true", help="print the current default and exit")
    args = parser.parse_args(argv)

    text = MCP_CONFIG.read_text()

    if args.show:
        print(current(text))
        return 0

    if not args.image:
        parser.error("--image is required unless --show is given")

    updated = rewrite(text, args.image)
    provenance = record(
        image=args.image,
        lock_text=LOCK.read_text(),
        version=version_of(INIT.read_text()),
    )

    if not args.write:
        print(updated, end="")
        print(f"== {PINNED_PACKS} ==")
        print(provenance, end="")
        return 0

    # The two files are written independently. Pinning the same digest twice is not
    # a no-op if the lock moved in between -- that is a re-tagged release of newer
    # content, and skipping the record would leave it describing the older packs.
    if updated == text:
        print(f"{MCP_CONFIG} already pins {args.image}")
    else:
        MCP_CONFIG.write_text(updated)
        print(f"pinned {MCP_CONFIG} to {args.image}")

    if PINNED_PACKS.exists() and PINNED_PACKS.read_text() == provenance:
        print(f"{PINNED_PACKS} already records these packs")
    else:
        PINNED_PACKS.write_text(provenance)
        print(f"recorded {PINNED_PACKS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
