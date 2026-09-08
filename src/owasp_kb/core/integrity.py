"""Invariants an index must satisfy before it may ship."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping

EXPECTED_REL_TYPES = {"guidance", "cwe", "supersedes", "nist"}

# CWE's own relationship graph, which only exists when the catalogue pack is
# ingested. Kept out of EXPECTED_REL_TYPES because that set is checked by
# absence -- requiring these unconditionally would fail every build that omits
# the pack. Requiring them when the pack IS present matters just as much: the
# entries can all land while Related_Weaknesses parsing produces nothing, and no
# other check in this module notices.
CATALOGUE_REL_TYPES = {"cwe_child", "cwe_peer", "cwe_member"}

# Mirrors embed.MAX_LENGTH (bge-small-en-v1.5's 512-token window). Duplicated
# rather than imported so this module stays free of any embedder coupling --
# it runs in the lite path too, where onnxruntime is not installed.
EMBEDDER_MAX_TOKENS = 512

# Chunks longer than the embedder's window have their tails truncated at
# embedding time, invisible to vector search. Some residual is genuinely
# unavoidable -- a single paragraph or fenced block longer than the window has
# no blank line to split on, and cutting mid-sentence to fit reads as corruption
# rather than as a long section -- but a regression in the chunker shows up as a
# jump here.
#
# Recalibrated after #38. The 4.6% this was originally set against was inflated
# by a defect: _split_oversized never size-checked its final block, so whether a
# document split depended on where its largest paragraph sat. With that fixed the
# measured share is 1.4% (68 chunks: 67 cheat sheets, 1 catalogue), and every one
# is an unsplittable block rather than an ordering accident.
#
# 8% against 1.4% would tolerate a sixfold regression, so the ceiling comes down
# to 4% -- still ample room for upstream content drift, and still well below the
# 11.9% the old 800-token default produced.
MAX_TRUNCATED_CHUNK_SHARE = 0.04

# Floors, not targets — set well below the measured real counts so ordinary
# upstream drift does not trip them, while a collapse to near-zero does.
# Measured against the pinned sources: guidance 167, cwe 204, supersedes 265,
# nist 48.
#
# The CWE graph floors are measured against CWE 4.20: 1,160 / 284 / 4,260. Note
# 1,160 rather than the 1,318 ChildOf declarations -- 158 are repeated and the
# links primary key stores distinct pairs. A rel absent entirely is skipped here
# (see the ``0 < count`` guard below) and handled by the rel-type checks instead,
# so listing the three costs a catalogue-less build nothing. These three sit at
# 30% headroom against measured, tighter than the 40-58% the ASVS-derived four
# carry, because CWE releases are additive: the graph grows between versions
# rather than churning, so less room is needed for legitimate drift.
MIN_EDGES_PER_REL = {
    "guidance": 100,
    "cwe": 100,
    "supersedes": 150,
    "nist": 20,
    "cwe_child": 800,
    "cwe_peer": 200,
    "cwe_member": 3000,
}


def run_checks(
    conn: sqlite3.Connection,
    *,
    expected_requirements: Mapping[str, int],
    check_edge_floors: bool = True,
) -> list[str]:
    """Return human-readable failures. Empty means the index is sound.

    ``expected_requirements`` is keyed by pack name rather than a single global
    total. With more than one checklist pack a total is meaningless -- ASVS and
    MASVS summed pass whether both packs are complete or one of them is short by
    exactly what the other is long, and a single number cannot tell which pack
    a shortfall came from. Counting per pack instead makes each pack's ingest
    accountable for its own rows.

    A checklist pack present in the database but absent from this mapping is
    itself a failure, not something silently skipped: an ingest that inserts
    zero rows for a newly wired pack would otherwise ship with nothing counting
    it, which is the defect class this project keeps hitting. Every pack the
    build ingests must be declared here, in ``build.EXPECTED_REQUIREMENTS``.

    ``check_edge_floors`` exists so small fixture databases can assert the
    structural checks without meeting production-scale edge counts.
    """
    failures: list[str] = []

    # LEFT JOIN so a checklist pack with zero requirement rows counts as 0
    # rather than vanishing from the result -- an ingest that silently inserts
    # nothing must still be compared against its expected count.
    pack_counts = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT p.name, COUNT(r.id) FROM packs p"
            " LEFT JOIN requirements r ON r.pack_id = p.id"
            " WHERE p.type = 'checklist'"
            " GROUP BY p.id"
        )
    }
    for name, expected in sorted(expected_requirements.items()):
        actual = pack_counts.get(name, 0)
        if actual != expected:
            failures.append(f"{name!r} requirement count is {actual}, expected {expected}")
    for name in sorted(pack_counts.keys() - expected_requirements.keys()):
        failures.append(
            f"checklist pack {name!r} has no expected requirement count declared; "
            "add one to build.EXPECTED_REQUIREMENTS so a shortfall fails the build"
        )

    empty = conn.execute("SELECT COUNT(*) FROM chunks WHERE TRIM(text) = ''").fetchone()[0]
    if empty:
        failures.append(f"{empty} empty chunk(s) present")

    chunkless = conn.execute(
        "SELECT d.doc_key FROM docs d"
        " LEFT JOIN sections s ON s.doc_id = d.id"
        " LEFT JOIN chunks c ON c.section_id = s.id"
        " GROUP BY d.id HAVING COUNT(c.id) = 0"
    ).fetchall()
    for row in chunkless:
        failures.append(f"document {row[0]!r} has no chunks")

    dangling = conn.execute(
        "SELECT DISTINCT to_id FROM links WHERE rel = 'guidance'"
        " AND to_id NOT IN (SELECT doc_key FROM docs)"
    ).fetchall()
    for row in dangling:
        failures.append(f"guidance link points at unknown document {row[0]!r}")

    orphan_reqs = conn.execute(
        "SELECT req_id FROM requirements WHERE chunk_id IS NULL"
        " OR chunk_id NOT IN (SELECT id FROM chunks)"
    ).fetchall()
    for row in orphan_reqs:
        failures.append(f"requirement {row[0]!r} has no chunk")

    unbalanced = conn.execute(
        "SELECT COUNT(*) FROM chunks"
        " WHERE (LENGTH(text) - LENGTH(REPLACE(text, '```', ''))) / 3 % 2 = 1"
    ).fetchone()[0]
    if unbalanced:
        failures.append(f"{unbalanced} chunk(s) contain an unbalanced code fence")

    # A relationship type that silently produces zero edges is the failure mode
    # that already bit this project: the CWE mapping is keyed on bleeding-edge
    # ids, so every entry was dropped and the drop-and-count design made a total
    # failure read as normal operation. owasp_related advertises all four, and
    # advertising a relationship that never exists is a silent lie.
    # catalogue_entries always exists -- create_schema creates every table -- so
    # this counts whether the pack is populated, not whether the table is present.
    has_catalogue = bool(conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0])

    present = {r[0] for r in conn.execute("SELECT DISTINCT rel FROM links")}
    expected_rels = EXPECTED_REL_TYPES | (CATALOGUE_REL_TYPES if has_catalogue else set())
    for rel in sorted(expected_rels - present):
        failures.append(
            f"no {rel!r} links were produced; owasp_related advertises this "
            "relationship, so zero edges means the mapping failed to resolve"
        )

    # Skipped when the CWE pack is absent: a build without the catalogue carries
    # the ASVS-to-CWE links with nothing to resolve them against, and that is not
    # a fault. Scoped to rel = 'cwe' exactly -- cwe_child/cwe_peer/cwe_member are
    # CWE's own graph, whose edges legitimately point outside an ingested subset,
    # so rel LIKE 'cwe%' would turn correct rows into a build failure.
    if has_catalogue:
        unresolved = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT l.to_id FROM links l"
                " WHERE l.rel = 'cwe'"
                " AND NOT EXISTS ("
                "  SELECT 1 FROM catalogue_entries e WHERE e.entry_id = l.to_id)"
            )
        ]
        if unresolved:
            shown = ", ".join(sorted(unresolved)[:5])
            # The population this check counts is the mapping *after* translation to
            # 5.0.0: 115 distinct ids, four of them Categories (CWE-255, 310, 320,
            # 1002). The upstream file has a fifth, CWE-16, but both of its only
            # citers are bleeding-edge ids that do not translate, so no build can
            # ever surface it here. That roster stays in this comment rather than in
            # the message: a build error should say what to fix, and a measurement
            # embedded in one is the clause that goes stale -- this one already did.
            failures.append(
                f"{len(unresolved)} ASVS-mapped CWE id(s) resolve to no catalogue "
                f"entry ({shown}). Either the CWE pack is stale relative to the "
                "mapping, or the ingest is dropping entries the mapping needs -- it "
                "must keep Categories as well as Weaknesses, and Deprecated and "
                "Obsolete entries too, because the mapping cites all of them"
            )

    total_chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    if total_chunks:
        truncated = conn.execute(
            "SELECT COUNT(*) FROM chunks WHERE token_est > ?", (EMBEDDER_MAX_TOKENS,)
        ).fetchone()[0]
        share = truncated / total_chunks
        if share > MAX_TRUNCATED_CHUNK_SHARE:
            failures.append(
                f"{truncated} of {total_chunks} chunks ({share:.1%}) exceed the embedder's "
                f"{EMBEDDER_MAX_TOKENS}-token window and would be truncated; expected at "
                f"most {MAX_TRUNCATED_CHUNK_SHARE:.0%}"
            )

    if check_edge_floors:
        for rel, minimum in sorted(MIN_EDGES_PER_REL.items()):
            count = conn.execute("SELECT COUNT(*) FROM links WHERE rel = ?", (rel,)).fetchone()[0]
            if 0 < count < minimum:
                failures.append(
                    f"only {count} {rel!r} links, expected at least {minimum}; "
                    "an upstream format change may be silently dropping entries"
                )

    return failures
