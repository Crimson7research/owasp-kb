"""Invariants an index must satisfy before it may ship."""

from __future__ import annotations

import sqlite3

EXPECTED_REL_TYPES = {"guidance", "cwe", "supersedes", "nist"}

# Floors, not targets — set well below the measured real counts so ordinary
# upstream drift does not trip them, while a collapse to near-zero does.
# Measured against the pinned sources: guidance 167, cwe 204, supersedes 265,
# nist 48.
MIN_EDGES_PER_REL = {
    "guidance": 100,
    "cwe": 100,
    "supersedes": 150,
    "nist": 20,
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
    present = {r[0] for r in conn.execute("SELECT DISTINCT rel FROM links")}
    for rel in sorted(EXPECTED_REL_TYPES - present):
        failures.append(
            f"no {rel!r} links were produced; owasp_related advertises this "
            "relationship, so zero edges means the mapping failed to resolve"
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
