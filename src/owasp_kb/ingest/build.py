"""Build the SQLite index from fetched sources."""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from sqlite3 import Connection

from owasp_kb.core.db import connect, finalize_for_readonly
from owasp_kb.core.integrity import run_checks
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.links import (
    ingest_cwe_links,
    ingest_guidance_links,
    ingest_nist_links,
    ingest_supersedes_links,
)
from owasp_kb.ingest.lock import Lock, load_lock
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets
from owasp_kb.ingest.packs.cwe import ingest_cwe

log = logging.getLogger(__name__)
EXPECTED_ASVS_REQUIREMENTS = 345


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

    requirements: int = 0
    documents: int = 0
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
    expected_requirements: int = EXPECTED_ASVS_REQUIREMENTS,
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


def _populate(
    conn: Connection,
    sources: Path,
    lock: Lock,
    *,
    expected_requirements: int,
    with_vectors: bool,
    check_edge_floors: bool,
) -> BuildReport:
    """Ingest every pack and every link set, then gate the result.

    Raises rather than cleaning up: the caller owns the file.
    """
    report = BuildReport()

    asvs_cfg = lock.packs["asvs"]
    report.requirements = ingest_asvs(
        conn,
        _one(sources / "asvs", "*flat.json"),
        version=asvs_cfg.version,
        license=asvs_cfg.license,
    )

    cs_cfg = lock.packs["cheatsheets"]
    report.documents = ingest_cheatsheets(
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
    parser.add_argument("--expected-requirements", type=int, default=EXPECTED_ASVS_REQUIREMENTS)
    parser.add_argument(
        "--no-edge-floors",
        action="store_true",
        help="skip minimum edge-count checks (for small fixture builds)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        report = build_index(
            args.sources,
            args.out,
            lock_path=args.lock,
            expected_requirements=args.expected_requirements,
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
        "built %s: %d requirements, %d documents, %d catalogue entries, %d chunks "
        "(%d truncated), %d guidance links, %d CWE links (%d dropped), %d supersedes links, "
        "%d NIST links (%d unmatched), %d vectors",
        args.out,
        report.requirements,
        report.documents,
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
