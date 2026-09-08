"""Merge numbered report sections into one file.

An assessment is produced in stages -- inventory, refutation, finding,
verification -- each leaving a durable result. The report was the only stage that
was not: 120,895 characters emitted in a single tool call at the end, after an
hour of work, depending on all of it surviving in one agent's context. An
interruption there loses the write, and the material to redo it is spread across
151 subagent transcripts.

Sections are written to
``${CLAUDE_CONFIG_DIR:-~/.claude}/owasp-kb/sessions/<session>/report/`` as they
become available, and merged here. The numeric prefix carries the order, so a
chapter roster can land when that chapter's verifiers return rather than when
its neighbours are ready.

This runs on the host rather than as an MCP tool: the server's state mount is
read-only and the target repository is not mounted at all, so nothing inside the
container can write the report.

The merge refuses rather than producing a report that looks complete:

* a duplicated number would silently drop a section
* a count that disagrees with the roster means a finding has no detail section
* an empty directory means nothing was written at all

Ordering is numeric, not lexicographic -- ``sorted()`` on filenames puts 1000
before 201, which would reorder a report with more than a hundred sections and
give no indication it had done so.
"""

from __future__ import annotations

import re
from pathlib import Path

from owasp_kb_cli.state import report_dir

SECTION = re.compile(r"^(\d+)_(.+)\.md$")


def collect(directory: Path) -> list[tuple[int, Path]]:
    """Every section, ordered by its numeric prefix.

    Raises on a duplicate prefix. Two sections numbered 301 are not a style
    problem: one of them would not appear in the report, and nothing downstream
    could tell.
    """
    found: dict[int, Path] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        match = SECTION.match(path.name)
        if not match:
            continue
        number = int(match.group(1))
        if number in found:
            raise SystemExit(
                f"error: sections {found[number].name} and {path.name} share the "
                f"number {number}. One of them would be dropped silently; renumber "
                "so each section is distinct."
            )
        found[number] = path
    return sorted(found.items())


def merge(session: str, out: Path, expect_findings: int | None) -> int:
    directory = report_dir(session)
    if not directory.is_dir():
        raise SystemExit(f"error: no report sections at {directory}")

    sections = collect(directory)
    if not sections:
        raise SystemExit(
            f"error: {directory} contains no NNN_name.md sections. An empty merge "
            "would write an empty report, which reads as an assessment result."
        )

    if expect_findings is not None:
        # Finding detail sections are the 300 block. A roster reporting 38
        # verified gaps against 37 sections means one finding has no detail, and
        # a reader cannot tell which.
        actual = sum(1 for number, _ in sections if 301 <= number < 400)
        if actual != expect_findings:
            raise SystemExit(
                f"error: the roster reports {expect_findings} findings and the "
                f"report has {actual} detail sections in the 300 block. Refusing "
                "to write a report that is missing one -- nothing downstream "
                "could detect the gap."
            )

    body = "\n\n".join(path.read_text().strip() for _, path in sections)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body + "\n")
    print(f"merged {len(sections)} sections into {out}")
    return 0
