"""Merging numbered report sections.

The report was the only stage of an assessment that was not incremental: 120,895
characters written in one call at the end, larger than the checklist call that
already proved undeliverable in #44. These pin the refusals, which are the reason
to do this at all -- a merge that quietly produces a short report is worse than
the single write it replaces.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TOOL = Path("plugins/owasp-kb/bin/owasp-kb")


def _sections(config_dir: Path, session: str, names: list[str]) -> Path:
    directory = config_dir / "owasp-kb" / "sessions" / session / "report"
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_text(f"content of {name}")
    return directory


def _merge(config_dir: Path, session: str, out: Path, *extra: str):
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "report",
            "merge",
            "--session",
            session,
            "--out",
            str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "CLAUDE_CONFIG_DIR": str(config_dir)},
    )


def test_sections_merge_in_numeric_order(tmp_path):
    _sections(tmp_path, "s1", ["101_summary.md", "100_title.md", "301_finding_1.md"])
    out = tmp_path / "report.md"
    result = _merge(tmp_path, "s1", out)
    assert result.returncode == 0, result.stderr
    body = out.read_text()
    assert body.index("100_title") < body.index("101_summary") < body.index("301_finding_1")


def test_ordering_is_numeric_not_lexicographic(tmp_path):
    """sorted() on filenames puts 1000 before 201. A report with more than a
    hundred sections would be silently reordered."""
    _sections(tmp_path, "s1", ["201_roster.md", "1000_appendix.md", "100_title.md"])
    out = tmp_path / "report.md"
    assert _merge(tmp_path, "s1", out).returncode == 0
    body = out.read_text()
    assert body.index("100_title") < body.index("201_roster") < body.index("1000_appendix")


def test_a_duplicate_number_refuses(tmp_path):
    """Two sections numbered 301: one would not appear, and nothing downstream
    could tell which."""
    _sections(tmp_path, "s1", ["301_finding_a.md", "301_finding_b.md"])
    result = _merge(tmp_path, "s1", tmp_path / "report.md")
    assert result.returncode != 0
    assert "301" in result.stderr
    assert not (tmp_path / "report.md").exists(), "refusal must not write a partial report"


def test_a_finding_count_mismatch_refuses(tmp_path):
    """The roster is the authority on how many findings exist. 38 reported
    against 37 sections means one finding has no detail."""
    _sections(tmp_path, "s1", ["100_title.md", "301_finding_1.md", "302_finding_2.md"])
    result = _merge(tmp_path, "s1", tmp_path / "report.md", "--expect-findings", "3")
    assert result.returncode != 0
    assert "3" in result.stderr and "2" in result.stderr
    assert not (tmp_path / "report.md").exists()


def test_a_matching_finding_count_merges(tmp_path):
    _sections(tmp_path, "s1", ["100_title.md", "301_finding_1.md", "302_finding_2.md"])
    out = tmp_path / "report.md"
    assert _merge(tmp_path, "s1", out, "--expect-findings", "2").returncode == 0
    assert out.exists()


def test_only_the_300_block_counts_as_a_finding(tmp_path):
    """The roster counts findings, not sections. Intros, rosters and refuted
    findings must not inflate the total and mask a genuinely missing one."""
    _sections(
        tmp_path,
        "s1",
        [
            "100_title.md",
            "201_roster_v1.md",
            "300_findings_intro.md",
            "301_finding_1.md",
            "401_refuted_1.md",
        ],
    )
    out = tmp_path / "report.md"
    assert _merge(tmp_path, "s1", out, "--expect-findings", "1").returncode == 0


def test_an_empty_directory_refuses(tmp_path):
    """An empty merge writes an empty report, which reads as an assessment
    result rather than as nothing having been written."""
    _sections(tmp_path, "s1", [])
    result = _merge(tmp_path, "s1", tmp_path / "report.md")
    assert result.returncode != 0
    assert not (tmp_path / "report.md").exists()


def test_a_missing_session_refuses(tmp_path):
    result = _merge(tmp_path, "never-ran", tmp_path / "report.md")
    assert result.returncode != 0


def test_files_that_are_not_sections_are_ignored(tmp_path):
    """A stray note or editor backup must not land in a client deliverable."""
    directory = _sections(tmp_path, "s1", ["100_title.md"])
    (directory / "notes.txt").write_text("scratch")
    (directory / "README").write_text("scratch")
    out = tmp_path / "report.md"
    assert _merge(tmp_path, "s1", out).returncode == 0
    assert "scratch" not in out.read_text()
