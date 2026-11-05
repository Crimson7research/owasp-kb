#!/usr/bin/env python3
"""Print the immutable image tag, derived from sources.lock.yml.

The tag names every pack in the index: it named two of three until the CWE
pack shipped, at which point a CWE release bump -- which deprecates ids and
renumbers others -- would have produced a byte-different index under an
identical tag. cwe_get makes CWE ids directly citable, so they are part of
what the reproducible-citation promise covers, and the tag has to be able to
distinguish them.

Before this script, the tag was composed by hand in two places -- the
Makefile and release.yml -- kept in step only by a comment asking a human to
update both. A MASVS bump would have reproduced the exact CWE failure a
second time, silently, because nothing checked that the tag named every pack
the lock declared. This is the one derivation both callers use instead.

See ADR 0015 and the PINNED_TAG comment this replaced in the Makefile.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

LOCK = Path("sources.lock.yml")

# The prefix each pack's version is stamped with in the tag. `cs` is not
# derivable from `cheatsheets` -- it is a published spelling, carried forward
# from before this script existed, and changing it would break continuity
# with tags already in the registry. So this is a lookup, not a rule.
PREFIXES = {
    "asvs": "asvs",
    "cheatsheets": "cs",
    "cwe": "cwe",
    "masvs": "masvs",
    "aisvs": "aisvs",
}

# Explicit rather than `sorted(lock.packs)`: this is the order the tag has
# always been built in, and a pack added to the lock must be appended after
# it, not alphabetised into the middle of a spelling that already ships on
# published images. Changing this order would change every future tag's
# spelling for packs that did not change, which is exactly the kind of churn
# an immutable tag exists to avoid.
ORDER = ["asvs", "cheatsheets", "cwe", "masvs", "aisvs"]


def pinned_tag(packs: dict[str, dict]) -> str:
    """The immutable tag naming every pack in `packs` (as loaded from the lock).

    Fails loudly on a pack this script has no prefix for -- that is the whole
    point: the next pack must fail the release rather than ship under a tag
    that does not name it.
    """
    undeclared = sorted(set(packs) - set(PREFIXES))
    if undeclared:
        raise SystemExit(
            f"error: {undeclared!r} has no tag prefix declared in scripts/pinned_tag.py. "
            "Add one to PREFIXES (and to ORDER) so the immutable tag names it -- "
            "otherwise a version bump for that pack ships under an unchanged tag."
        )
    ordered = ORDER + sorted(set(packs) - set(ORDER))
    return "-".join(f"{PREFIXES[name]}{packs[name]['version']}" for name in ordered)


def main(argv: list[str] | None = None) -> int:
    if argv:
        raise SystemExit("error: pinned_tag.py takes no arguments")
    packs = yaml.safe_load(LOCK.read_text())["packs"]
    print(pinned_tag(packs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
