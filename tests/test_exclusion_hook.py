"""The PreToolUse hook that keeps an excluded prior assessment out of context.

A finder grepped the excluded report and quoted the hit, having read "do not
open them" as permitting a grep. The orchestrator caught it; nothing mechanical
did. These pin both halves of the fix: that the hook blocks what it should, and
-- more important -- that it cannot affect a session that never ran an
assessment.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path("plugins/owasp-kb/hooks/block_excluded_reads.py")
EXCLUDED = "docs/security/asvs-5.0.0-l2-firmware.md"


def _run(payload: dict | str, config_dir: Path) -> dict | None:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=raw,
        capture_output=True,
        text=True,
        env={**os.environ, "CLAUDE_CONFIG_DIR": str(config_dir)},
    )
    assert result.returncode == 0, f"hook must never fail the call: {result.stderr}"
    return json.loads(result.stdout) if result.stdout.strip() else None


def _denied(out: dict | None) -> bool:
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.fixture
def config_dir(tmp_path):
    listing = tmp_path / "owasp-kb" / "sessions" / "sess-1"
    listing.mkdir(parents=True)
    (listing / "excluded").write_text(f"{EXCLUDED}\n")
    return tmp_path


def _call(tool, session="sess-1", **tool_input):
    return {"session_id": session, "tool_name": tool, "tool_input": tool_input}


def test_a_direct_read_of_the_excluded_report_is_denied(config_dir):
    assert _denied(_run(_call("Read", file_path=EXCLUDED), config_dir))


def test_a_broad_grep_that_would_sweep_it_is_denied(config_dir):
    """The observed violation: greps rooted at docs/ recursed into it. The hook
    cannot filter output, so the call is refused rather than the hits stripped
    -- by the time they are stripped the text has already arrived."""
    assert _denied(_run(_call("Grep", pattern="session", path="docs"), config_dir))


def test_a_repo_wide_grep_with_no_path_is_denied(config_dir):
    assert _denied(_run(_call("Grep", pattern="session"), config_dir))


def test_a_grep_that_excludes_the_path_explicitly_is_allowed(config_dir):
    """The way through. The agent states the exclusion instead of discarding
    hits after seeing them."""
    out = _run(_call("Grep", pattern="session", path="docs", glob=f"!{EXCLUDED}"), config_dir)
    assert not _denied(out)


def test_the_search_pattern_is_not_mistaken_for_a_file_filter(config_dir):
    """Grep's `pattern` is the search regex; only `glob` narrows which files are
    read. Treating a wildcard-free pattern as a narrow glob let the broad grep
    through -- the exact case this hook exists for."""
    assert _denied(_run(_call("Grep", pattern="no-wildcards-here", path="docs"), config_dir))


def test_a_search_of_an_unrelated_tree_is_allowed(config_dir):
    assert not _denied(_run(_call("Grep", pattern="x", path="firmware"), config_dir))


def test_an_unrelated_file_is_allowed(config_dir):
    assert not _denied(_run(_call("Read", file_path="firmware/core/src/x.cpp"), config_dir))


# -- isolation: the property that lets this ship at all ----------------------


def test_another_session_is_untouched(config_dir):
    """The list is keyed on the session that wrote it. A session that never ran
    an assessment looks for a file named after itself, finds none, and is
    unaffected -- structurally, not by policy."""
    assert not _denied(_run(_call("Read", session="sess-other", file_path=EXCLUDED), config_dir))


def test_no_exclusion_list_allows_everything(tmp_path):
    assert not _denied(_run(_call("Read", file_path=EXCLUDED), tmp_path))


@pytest.mark.parametrize(
    "payload",
    ["not json", "", '{"tool_name":"Read"}', '{"session_id":"sess-1"}'],
    ids=["malformed", "empty", "no-session", "no-tool"],
)
def test_an_unusable_payload_allows_the_call(payload, config_dir):
    """Fails open on purpose. A hook that failed closed would break unrelated
    sessions on a bug of its own, which is worse than the leak it prevents --
    owasp_roster rejecting findings that cite an excluded path is the real
    gate."""
    assert not _denied(_run(payload, config_dir))


def test_the_denial_says_how_to_proceed(config_dir):
    """A refusal an agent cannot act on gets worked around."""
    out = _run(_call("Grep", pattern="session", path="docs"), config_dir)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert EXCLUDED in reason
    assert "--glob" in reason
    assert "INSUFFICIENT EVIDENCE" in reason
