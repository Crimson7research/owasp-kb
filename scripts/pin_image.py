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

See ADR 0014.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MCP_CONFIG = Path("plugins/owasp-kb/.mcp.json")

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
    if not args.write:
        print(updated, end="")
        return 0

    if updated == text:
        print(f"{MCP_CONFIG} already pins {args.image}")
        return 0

    MCP_CONFIG.write_text(updated)
    print(f"pinned {MCP_CONFIG} to {args.image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
