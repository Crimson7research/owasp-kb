"""Build the SQLite index from fetched sources."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from sqlite3 import Connection

from owasp_kb.core.db import connect, finalize_for_readonly
from owasp_kb.core.integrity import run_checks
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import (
    ingest_aisvs_guidance_links,
    ingest_cwe_links,
    ingest_guidance_links,
    ingest_nist_links,
    ingest_supersedes_links,
)
from owasp_kb.ingest.lock import Lock, load_lock
from owasp_kb.ingest.packs.aisvs import ingest_aisvs
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.ingest.packs.cwe import ingest_cwe
from owasp_kb.ingest.packs.masvs import ingest_masvs

log = logging.getLogger(__name__)

# One entry per checklist pack the lock declares. run_checks fails the build if
# a checklist pack in the database is missing here, so a newly wired pack must
# be added in the same change that calls its ingest -- not left to be noticed
# later as a silently uncounted shortfall.
#
# asvs is the pre-existing figure, pinned only here. masvs is measured against
# the pinned v2.1.0 release asset (8 groups, 24 controls) and is also asserted by
# test_the_real_release_matches_the_shape_the_build_expects in
# tests/ingest/test_masvs.py, which skips without data/ and runs in the realdata
# selection -- so an upstream reshuffle fails there, naming the shape that moved,
# rather than only here as a count mismatch during a full build.
#
# aisvs is measured against tag v1.01, folder 1.01/en/: 214 requirement rows, one
# of them the removed 10.2.6, so 213. Also asserted, with its 57/110/46 level
# split, by test_the_real_release_matches_the_shape_the_build_expects in
# tests/ingest/test_aisvs.py.
EXPECTED_REQUIREMENTS = {"aisvs": 213, "asvs": 345, "masvs": 24}


@dataclass
class BuildReport:
    """What a build produced.

    Every count here comes from the ingest that inserted the rows, or from a
    COUNT over the table that holds them -- never from the ``packs`` table.
    That distinction matters: ``upsert_pack`` commits the pack row before any
    entry is inserted, so a pack row is evidence that an ingest started, not
    that it produced anything. A report that enumerated ``packs`` and then
    counted entries would render a failed catalogue ingest as a pack that
    exists and happens to be empty.
    """

    # One count per pack, each named for what that pack produces: ASVS
    # requirements, cheat sheet documents, CWE catalogue entries. Deliberately not
    # `documents`, which is what this field was called while holding only the cheat
    # sheet count -- the build then logged "120 documents" for an index whose `docs`
    # table has 1,528 rows, and a reader diffing that against docs/stack.md saw a 12x
    # gap with no explanation. `chunks` below is a whole-index COUNT, so the two
    # scopes sat in one log line looking alike.
    requirements: int = 0
    masvs_requirements: int = 0
    aisvs_requirements: int = 0
    cheatsheet_documents: int = 0
    catalogue_entries: int = 0
    chunks: int = 0
    guidance_links: int = 0
    cwe_links: int = 0
    cwe_dropped: int = 0
    supersedes_links: int = 0
    nist_links: int = 0
    nist_skipped: int = 0
    vectors: int = 0
    truncated_chunks: int = 0
    integrity_failures: list[str] = field(default_factory=list)


def _one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if not matches:
        raise FileNotFoundError(f"no file matching {pattern!r} under {directory}")
    return matches[0]


def build_index(
    sources_dir: str | Path,
    out_path: str | Path,
    *,
    lock_path: str | Path = "sources.lock.yml",
    expected_requirements: Mapping[str, int] = EXPECTED_REQUIREMENTS,
    with_vectors: bool = False,
    check_edge_floors: bool = True,
) -> BuildReport:
    """Build an index. Raises RuntimeError if integrity checks fail.

    Owns the output file's whole lifecycle: nothing that fails part-way leaves an
    index behind. That used to hold only for an integrity failure, which was the
    only failure the build had. It is not any more -- ``ingest_cwe`` rejects a
    catalogue that parses but yields no entries, which is what an upstream
    namespace bump produces, and the pack row it already committed would have sat
    in a half-written file that looks publishable.
    """
    sources, out = Path(sources_dir), Path(out_path)
    lock = load_lock(lock_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    conn = connect(out, load_vec=with_vectors)
    try:
        create_schema(conn)
        report = _populate(
            conn,
            sources,
            lock,
            expected_requirements=expected_requirements,
            with_vectors=with_vectors,
            check_edge_floors=check_edge_floors,
        )
    except BaseException:
        conn.close()
        out.unlink(missing_ok=True)
        raise

    conn.execute("PRAGMA optimize")
    # Must run before the file is packaged: WAL mode persists in the header and a
    # WAL index cannot be opened read-only from the image's non-writable directory.
    finalize_for_readonly(conn)
    conn.close()
    return report


def _ingest_checklists(conn: Connection, sources: Path, lock: Lock, report: BuildReport) -> None:
    """Ingest the three checklist packs, recording each count on ``report``."""
    asvs_cfg = lock.packs["asvs"]
    report.requirements = ingest_asvs(
        conn,
        _one(sources / "asvs", "*flat.json"),
        version=asvs_cfg.version,
        license=asvs_cfg.license,
    )

    # Indexed like the other packs -- a KeyError if the lock stops declaring it,
    # rather than a silent skip. The asset's filename carries no version number
    # (unlike the ASVS and CWE assets above, which do and so are matched by
    # glob through _one()), so a direct path is used instead.
    masvs_cfg = lock.packs["masvs"]
    report.masvs_requirements = ingest_masvs(
        conn,
        sources / "masvs" / "OWASP_MASVS.yaml",
        version=masvs_cfg.version,
        license=masvs_cfg.license,
    )

    # Fetched as the chapter Markdown itself -- AISVS's only release asset is a
    # PDF -- so the ingest is handed the directory and globs the chapters.
    aisvs_cfg = lock.packs["aisvs"]
    report.aisvs_requirements = ingest_aisvs(
        conn,
        sources / "aisvs",
        version=aisvs_cfg.version,
        license=aisvs_cfg.license,
    )


def _populate(
    conn: Connection,
    sources: Path,
    lock: Lock,
    *,
    expected_requirements: Mapping[str, int],
    with_vectors: bool,
    check_edge_floors: bool,
) -> BuildReport:
    """Ingest every pack and every link set, then gate the result.

    Raises rather than cleaning up: the caller owns the file.
    """
    report = BuildReport()

    _ingest_checklists(conn, sources, lock, report)

    cs_cfg = lock.packs["cheatsheets"]
    report.cheatsheet_documents = ingest_cheatsheets(
        conn,
        sources / "cheatsheets" / "cheatsheets",
        version=cs_cfg.version,
        commit_sha=cs_cfg.commit,
        license=cs_cfg.license,
    )

    # Indexed like the other two -- a KeyError if the lock stops declaring it,
    # rather than a silent skip. A build that quietly omitted the catalogue would
    # leave the ASVS-to-CWE mapping unresolvable and both CWE integrity checks
    # inert, which is the state this pack exists to end.
    #
    # Before the mapping links below, so the entries a citation resolves against
    # are in place before anything points at them.
    cwe_cfg = lock.packs["cwe"]
    report.catalogue_entries = ingest_cwe(
        conn,
        _one(sources / "cwe", "cwec_v*.xml"),
        version=cwe_cfg.version,
        license=cwe_cfg.license,
    )

    report.guidance_links = ingest_guidance_links(conn, sources / "cheatsheets" / "IndexASVS.md")
    report.guidance_links += ingest_aisvs_guidance_links(
        conn, sources / "aisvs", sources / "cheatsheets" / "cheatsheets"
    )
    report.cwe_links, report.cwe_dropped = ingest_cwe_links(
        conn,
        _one(sources / "asvs", "*cwe_mapping.json"),
        be_to_release_path=_one(sources / "asvs", "mapping_v5.0.be_to_v5*.yml"),
    )
    # Order matters: NIST edges are composed through the supersedes edges.
    report.supersedes_links, _ = ingest_supersedes_links(
        conn, _one(sources / "asvs", "mapping_v5.0.0_to_v4*.yml")
    )
    report.nist_links, report.nist_skipped = ingest_nist_links(conn, sources / "asvs" / "nist.md")

    if with_vectors:
        from owasp_kb.core.embed import Embedder
        from owasp_kb.core.retrieval.hybrid import index_vectors

        report.vectors = index_vectors(conn, Embedder())

    report.chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    from owasp_kb.core.embed import MAX_LENGTH

    report.truncated_chunks = conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE token_est > ?", (MAX_LENGTH,)
    ).fetchone()[0]

    report.integrity_failures = run_checks(
        conn,
        expected_requirements=expected_requirements,
        check_edge_floors=check_edge_floors,
    )
    if report.integrity_failures:
        raise RuntimeError(
            "index integrity checks failed, refusing to publish:\n  - "
            + "\n  - ".join(report.integrity_failures)
        )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the OWASP KB index")
    parser.add_argument("--sources", default="data")
    parser.add_argument("--out", default="dist/owasp-kb.sqlite")
    parser.add_argument("--lock", default="sources.lock.yml")
    parser.add_argument("--with-vectors", action="store_true")
    parser.add_argument(
        "--expected-requirements",
        action="append",
        metavar="PACK=COUNT",
        help=(
            "expected requirement count for one checklist pack, as PACK=COUNT "
            "(e.g. asvs=345); repeatable, one per pack. Defaults to the figures "
            "in EXPECTED_REQUIREMENTS for every pack the build ingests."
        ),
    )
    parser.add_argument(
        "--no-edge-floors",
        action="store_true",
        help="skip minimum edge-count checks (for small fixture builds)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.expected_requirements is None:
        expected_requirements = EXPECTED_REQUIREMENTS
    else:
        expected_requirements = {}
        for pair in args.expected_requirements:
            pack, sep, count = pair.partition("=")
            if not sep or not pack or not count:
                log.error(
                    "invalid --expected-requirements %r; expected PACK=COUNT, e.g. asvs=345",
                    pair,
                )
                return 1
            try:
                expected_requirements[pack] = int(count)
            except ValueError:
                log.error("invalid --expected-requirements %r; COUNT must be an integer", pair)
                return 1

    try:
        report = build_index(
            args.sources,
            args.out,
            lock_path=args.lock,
            expected_requirements=expected_requirements,
            with_vectors=args.with_vectors,
            check_edge_floors=not args.no_edge_floors,
        )
    # ValueError is how a pack rejects its own source -- ingest_cwe raises it for a
    # catalogue that parses but yields no entries. Uncaught it exits non-zero by
    # traceback anyway, so this is here for the actionable log line, not the code.
    except (RuntimeError, FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 1

    log.info(
        "built %s: %d ASVS requirements, %d MASVS controls, %d AISVS requirements, "
        "%d cheat sheet documents, "
        "%d CWE catalogue entries, %d chunks index-wide (%d truncated), %d guidance "
        "links, %d CWE links (%d dropped), %d supersedes links, %d NIST links "
        "(%d unmatched), %d vectors",
        args.out,
        report.requirements,
        report.masvs_requirements,
        report.aisvs_requirements,
        report.cheatsheet_documents,
        report.catalogue_entries,
        report.chunks,
        report.truncated_chunks,
        report.guidance_links,
        report.cwe_links,
        report.cwe_dropped,
        report.supersedes_links,
        report.nist_links,
        report.nist_skipped,
        report.vectors,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
