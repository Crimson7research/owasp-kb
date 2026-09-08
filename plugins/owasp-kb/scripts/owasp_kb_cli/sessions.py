"""List and clear the assessment state an engagement leaves on this machine.

An assessment writes findings, a scope inventory and its report sections to
``sessions/<id>/`` under the plugin's state directory, and nothing removed them.
On a consultant's machine that accumulates one engagement's material per session,
indefinitely, under opaque session ids.

Nothing here runs on a timer and nothing expires on its own: deleting an
assessment's record is a person's decision. This makes it visible and makes it
possible.

It deliberately does not report which codebase a session assessed. Target identity
was removed from recorded state on purpose, and a listing tool that recovered it
would undo that. A session is identified by date and volume instead.
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from owasp_kb_cli.state import sessions_dir, validate_session_id


@dataclass(frozen=True)
class Summary:
    session: str
    mtime: float
    findings: int
    sections: int
    has_inventory: bool
    bytes: int
    path: Path


def _tree_bytes(directory: Path) -> int:
    return sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())


def summarise(directory: Path) -> Summary:
    findings_file = directory / "findings.jsonl"
    findings = 0
    if findings_file.is_file():
        findings = sum(1 for line in findings_file.read_text().splitlines() if line.strip())
    report = directory / "report"
    sections = len(list(report.glob("*.md"))) if report.is_dir() else 0
    return Summary(
        session=directory.name,
        mtime=directory.stat().st_mtime,
        findings=findings,
        sections=sections,
        has_inventory=(directory / "inventory.md").is_file(),
        bytes=_tree_bytes(directory),
        path=directory,
    )


def list_sessions() -> list[Summary]:
    root = sessions_dir()
    if not root.is_dir():
        return []
    return sorted(
        (summarise(p) for p in root.iterdir() if p.is_dir()),
        key=lambda s: s.mtime,
    )


def older_than(days: int) -> list[Summary]:
    cutoff = time.time() - days * 86400
    return [s for s in list_sessions() if s.mtime < cutoff]


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.0f}GB"


def render(summaries: list[Summary]) -> None:
    if not summaries:
        print(f"no sessions under {sessions_dir()}")
        return
    print(f"{sessions_dir()}\n")
    for s in summaries:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s.mtime))
        inventory = "inventory" if s.has_inventory else "no inventory"
        print(
            f"  {s.session}  {when}  {s.findings} findings  "
            f"{s.sections} report sections  {inventory}  {_human(s.bytes)}"
        )
    total = sum(s.bytes for s in summaries)
    print(f"\n{len(summaries)} session(s), {_human(total)} total")
    print("This is assessment material. `owasp-kb sessions purge <id> --yes` removes one.")


def purge(ids: list[str], confirmed: bool) -> int:
    """Delete the named sessions. Returns non-zero if nothing was deleted.

    All-or-nothing: every id is resolved before anything is removed. A partial
    purge across a batch would leave the operator unable to say which sessions
    survived, which is the one thing this command exists to make knowable.
    """
    root = sessions_dir()
    targets: list[Path] = []
    for raw in ids:
        try:
            session = validate_session_id(raw)
        except ValueError as error:
            print(f"refusing: {error}")
            return 1
        directory = root / session
        if not directory.is_dir():
            print(f"refusing: no session {session} under {root}")
            return 1
        targets.append(directory)

    for directory in targets:
        summary = summarise(directory)
        print(
            f"would delete {directory}\n"
            f"  {summary.findings} findings, {summary.sections} report sections, "
            f"{_human(summary.bytes)}"
        )

    if not confirmed:
        print("\nNothing deleted. Re-run with --yes to delete the above.")
        return 1

    for directory in targets:
        shutil.rmtree(directory)
        print(f"deleted {directory}")
    return 0
