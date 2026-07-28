"""Invariants an index must satisfy before it may ship."""

from __future__ import annotations

import sqlite3

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
# embedding time, invisible to vector search. Some residual is unavoidable --
# a single oversized fenced code block cannot be split without corrupting it --
# but a regression in the chunker would show up as a jump here. Measured 4.6%
# at the current default; the floor sits above that with room for upstream
# content drift, and well below the 11.9% the old 800-token default produced.
MAX_TRUNCATED_CHUNK_SHARE = 0.08

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
    expected_requirements: int,
    check_edge_floors: bool = True,
) -> list[str]:
    """Return human-readable failures. Empty means the index is sound.

    ``check_edge_floors`` exists so small fixture databases can assert the
    structural checks without meeting production-scale edge counts.
    """
    failures: list[str] = []

    actual = conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0]
    if actual != expected_requirements:
        failures.append(f"requirement count is {actual}, expected {expected_requirements}")

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
            failures.append(
                f"{len(unresolved)} ASVS-mapped CWE id(s) resolve to no catalogue "
                f"entry ({shown}). Either the CWE pack is stale relative to the "
                "mapping, or the ingest is dropping entries the mapping needs -- "
                "measured against ASVS 5.0.0 and CWE 4.20, five of the 120 mapped "
                "ids are Categories rather than Weaknesses (CWE-16, 255, 310, 320, "
                "1002), so an ingest that kept only Weaknesses would strand all five"
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
