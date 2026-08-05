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


ABSOLUTE = f"/home/you/src/target/{EXCLUDED}"


def _listing(tmp_path, *paths):
    session = tmp_path / "owasp-kb" / "sessions" / "sess-1"
    session.mkdir(parents=True)
    (session / "excluded").write_text("".join(f"{p}\n" for p in paths))
    return tmp_path


@pytest.mark.parametrize("listed", [EXCLUDED, ABSOLUTE], ids=["relative", "absolute"])
@pytest.mark.parametrize(
    "root", ["docs", "./docs", "/home/you/src/target/docs"], ids=["rel", "dot", "abs"]
)
def test_a_rooted_search_is_denied_whichever_form_each_side_uses(tmp_path, listed, root):
    """A search rooted at a directory containing the report is the violation
    actually observed, and the root and the listed path arrive in whichever form
    their writer happened to use.

    Comparing them as strings meant only matching pairs lined up -- and because
    the root was normalised by stripping its leading slash while the listed path
    kept one, an absolute root matched nothing at all and every such search was
    allowed. All six combinations are denied now, so the list needs one entry per
    report rather than one per form the agent might use.
    """
    assert _denied(_run(_call("Grep", pattern="session", path=root), _listing(tmp_path, listed)))


@pytest.mark.parametrize("listed", [EXCLUDED, ABSOLUTE], ids=["relative", "absolute"])
def test_a_named_file_is_denied_whichever_form_each_side_uses(tmp_path, listed):
    """The same independence for a call naming the file, which the bidirectional
    suffix match already gave."""
    listing = _listing(tmp_path, listed)
    for cited in (EXCLUDED, ABSOLUTE):
        assert _denied(_run(_call("Read", file_path=cited), listing))


def test_a_sibling_tree_sharing_no_segment_chain_is_still_allowed(tmp_path):
    """The generosity has a floor. Segment matching would be worthless if it
    denied every search, so a root that shares no chain with the excluded path
    stays allowed -- otherwise the hook stops the assessment rather than the leak.
    """
    listing = _listing(tmp_path, ABSOLUTE)
    assert not _denied(
        _run(_call("Grep", pattern="x", path="/home/you/src/target/firmware"), listing)
    )


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


# -- what a search pattern can actually reach --------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["**/README.md", "docs/*.md", "path/to/OneNamedFile.cs", "src/**/*.py"],
    ids=["other-name", "one-level", "exact-file", "other-extension"],
)
def test_a_glob_that_cannot_expand_to_the_excluded_path_is_allowed(config_dir, pattern):
    """`Glob` states its file filter in `pattern`, and the hook only ever read `glob` --
    so every pathless `Glob` fell through to the deny whatever it asked for. 76 of them in
    one run, against agents that already carried the exclusion list in their prompt.

    `docs/*.md` is the sharp case: `*` does not cross `/`, so it reaches `docs/rep.md` and
    can never reach `docs/security/rep.md`.
    """
    assert not _denied(_run(_call("Glob", pattern=pattern), config_dir))


@pytest.mark.parametrize(
    "pattern",
    ["**/*.md", "docs/**/*.md", "**/*", "docs/**"],
    ids=["any-md", "docs-md", "everything", "docs-tree"],
)
def test_a_glob_that_can_expand_to_the_excluded_path_is_denied(config_dir, pattern):
    assert _denied(_run(_call("Glob", pattern=pattern), config_dir))


def test_a_glob_bounded_by_path_into_the_excluded_tree_is_denied(config_dir):
    """The case the hook exists for. A fix that reads the pattern but forgets that `path`
    still bounds the search would allow exactly this one."""
    assert _denied(_run(_call("Glob", path="docs/security", pattern="**/*"), config_dir))


def test_a_glob_bounded_by_path_away_from_it_is_allowed(config_dir):
    assert not _denied(_run(_call("Glob", path="firmware", pattern="**/*.md"), config_dir))


def test_an_absolute_glob_rooted_above_the_excluded_path_is_denied(tmp_path):
    """An absolute pattern is matched against the `/`-prefixed chain, so it lines up with
    an absolute list entry."""
    listing = _listing(tmp_path, ABSOLUTE)
    assert _denied(_run(_call("Glob", pattern="/home/you/src/target/**"), listing))


# -- negated selectors ---------------------------------------------------------


@pytest.mark.parametrize("glob", ["!*.py", "!node_modules/**"], ids=["extension", "tree"])
def test_a_negated_glob_that_still_sweeps_the_excluded_path_is_denied(config_dir, glob):
    """`!X` searches everything *except* `X`. Reading the `!` as a literal character made
    every negation unmatchable and so allowed -- in the one syntax this hook's own deny
    message tells agents to use."""
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["!**/*.md", "!docs/**"], ids=["extension", "tree"])
def test_a_negated_glob_that_covers_the_excluded_path_is_allowed(config_dir, glob):
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    ["!security/*.md", "!security/**"],
    ids=["anchored-partial", "anchored-tree"],
)
def test_a_negation_that_does_not_actually_exclude_the_path_is_denied(config_dir, glob):
    """ripgrep anchors a glob containing `/` to the search root, so `security/*.md` never
    matches `docs/security/...` and the negation excludes nothing. Reusing the
    over-approximating `_selects` here and inverting it read these as exclusions and let
    the report through -- verified against real ripgrep, which still finds the report
    under both of these."""
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


def test_a_negation_naming_an_unrelated_absolute_tree_is_denied(config_dir):
    assert _denied(_run(_call("Grep", pattern="session", glob="!/elsewhere/docs/**"), config_dir))


@pytest.mark.parametrize(
    "glob",
    ["!*.md", "!asvs-5.0.0-l2-firmware.md", "!docs/**", "!*/security/*.md"],
    ids=["extension", "basename", "anchored", "anchored-with-leading-wildcard"],
)
def test_a_negation_that_does_exclude_the_path_is_allowed(config_dir, glob):
    """A glob without `/` matches a basename at any depth; one with `/` is anchored and
    here does cover the recorded path -- `*/security/*.md` included: its three segments
    (`*`, `security`, `*.md`) line up with `docs/security/<file>.md` exactly, which a real
    ripgrep confirms by finding no match under this negation.

    The bare filename is the single most likely negation an agent writes when told to
    exclude a named report, and ripgrep confirms it excludes it.
    """
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    [
        "!./docs/**",
        "!docs/../docs/**",
        "!docs//security/*",
        "!docs/./security/*",
        "!docs/security/../security/*",
    ],
    ids=["dot-prefix", "walk-back", "empty-segment", "dot-segment", "walk-back-inner"],
)
def test_a_negation_ripgrep_cannot_honour_is_denied(config_dir, glob):
    """ripgrep matches a glob against the walked path verbatim -- `.`, `..` and an empty
    segment are literal components there, so none of these exclude anything. Normalising
    the pattern first made the hook believe each one covered the report while ripgrep
    handed it over. Verified against rg 15.2.0.

    `_selects` normalises for the opposite reason: over-approximating there is a denial.
    """
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["!/docs/**", "!/docs/security/*"], ids=["tree", "dir"])
def test_a_root_anchored_negation_is_allowed(config_dir, glob):
    """A leading `/` anchors to the search root rather than naming an absolute path, so
    these do exclude the report."""
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    ["!/*.md", "!/asvs-5.0.0-l2-firmware.md", "!/asvs-*.md", "!/*firmware*"],
    ids=["extension", "exact-name", "prefix", "substring"],
)
def test_a_root_anchored_single_component_negation_is_denied(config_dir, glob):
    """A leading `/` anchors the glob to the search root, which is exactly what stops it
    matching a basename at any depth. Stripping the `/` before deciding whether the glob
    was anchored sent these down the any-depth branch, so the hook read them as excluding
    a report that sits three levels down and ripgrep hands over."""
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["!docs/", "!docs/security/"], ids=["tree", "subdir"])
def test_a_trailing_slash_directory_negation_is_allowed(config_dir, glob):
    """A trailing `/` means "this directory" in gitignore syntax; ripgrep excludes
    everything under it, not just a literal empty final path segment."""
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    ["!firmware/", "!docs/security/*.md/"],
    ids=["unrelated-tree", "wildcard-then-slash"],
)
def test_a_trailing_slash_negation_that_does_not_cover_is_denied(config_dir, glob):
    """`firmware/` names a directory the excluded path never passes through. A wildcard
    segment immediately before the slash asks the excluded file itself to be a directory,
    which it is not -- ripgrep does not exclude it under either glob."""
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


# -- Glob has no negation syntax -----------------------------------------------


@pytest.mark.parametrize("pattern", ["!*.py", "!**/*.cs"], ids=["extension", "recursive"])
def test_a_bang_in_a_glob_pattern_is_a_filename_character(config_dir, pattern):
    """`Glob` has no negation syntax. Treating a leading `!` as one denied patterns that
    cannot reach the path -- the #33 failure, reintroduced by the negation fix."""
    assert not _denied(_run(_call("Glob", pattern=pattern), config_dir))


# -- form mismatch between an absolute pattern and a relative list entry ------


def test_an_absolute_glob_is_denied_against_a_relative_list_entry(config_dir):
    """The two forms share no root, so no suffix of the excluded path lines up with the
    pattern as written. Matching the remainder after the pattern's literal leading
    directory is the comparison that does not need to know the root."""
    pattern = "/home/you/src/target/docs/**/*.md"
    assert _denied(_run(_call("Glob", pattern=pattern), config_dir))


@pytest.mark.parametrize(
    "pattern",
    ["/home/you/src/target/**", "/home/you/src/target/**/*.md"],
    ids=["whole-tree", "tree-md"],
)
def test_a_broad_absolute_glob_is_denied_against_a_relative_list_entry(config_dir, pattern):
    """The broadest absolute globs are the ones an agent writes. Matching on the literal
    prefix only caught patterns that already named a directory inside the excluded path."""
    assert _denied(_run(_call("Glob", pattern=pattern), config_dir))


def test_an_absolute_glob_of_an_unrelated_tree_stays_allowed(config_dir):
    """The remainder after the literal prefix still decides, so precision survives."""
    pattern = "/home/you/src/target/firmware/**/*.cs"
    assert not _denied(_run(_call("Glob", pattern=pattern), config_dir))


# -- the suffix chain is what makes a mismatched root line up -----------------


def test_a_pattern_matches_below_a_prefix_the_list_entry_carries(tmp_path):
    """The search root is not knowable, so the pattern is tried against every suffix of
    the excluded path. A list entry recorded from the repository root, against an agent
    globbing from a package directory, only lines up on a suffix."""
    listing = _listing(tmp_path, f"packages/app/{EXCLUDED}")
    assert _denied(_run(_call("Glob", pattern="docs/**/*.md"), listing))


# -- .. segments do not let a pattern walk around the match -------------------


def test_a_pattern_that_walks_back_up_is_still_denied(config_dir):
    assert _denied(_run(_call("Glob", pattern="docs/../docs/**/*.md"), config_dir))


# -- Grep's own filter field ---------------------------------------------------


@pytest.mark.parametrize(
    "glob",
    ["*.py", "**/*.py", "src/**/*.ts"],
    ids=["extension", "recursive-extension", "other-tree"],
)
def test_a_grep_narrowed_to_files_it_cannot_reach_is_allowed(config_dir, glob):
    """The same defect on `Grep`'s own filter field. The replaced check allowed a glob only
    when it contained no wildcard at all, so `--glob '*.py'` was refused although a `.py`
    filter cannot reach a `.md` report -- 11 of the 87 denials in one run."""
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["*.md", "docs/**"], ids=["extension", "tree"])
def test_a_grep_narrowed_to_files_it_can_reach_is_denied(config_dir, glob):
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


# -- brace lists ---------------------------------------------------------------
#
# Every expectation below was run against rg 15.2.0 on a tree holding the excluded report,
# and records whether that ripgrep still returned it.


@pytest.mark.parametrize("glob", ["*.{ts,tsx}", "**/*.{js,jsx}"], ids=["flat", "recursive"])
def test_a_brace_list_that_cannot_reach_it_is_allowed(config_dir, glob):
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["*.{md,txt}", "docs/**/*.{md,rst}"], ids=["flat", "recursive"])
def test_a_brace_list_that_can_reach_it_is_denied(config_dir, glob):
    """`full_match` has no brace support, so an unexpanded `*.{md,txt}` matches nothing at
    all and the call is allowed. That is a leak rather than a rough edge."""
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["!*.{md,txt}", "!docs/**/*.{md,rst}"], ids=["flat", "recursive"])
def test_a_negated_brace_list_that_covers_the_path_is_allowed(config_dir, glob):
    """A negation is the mirror: it covers the path when any alternative matches it, and
    an unexpanded brace list matched nothing -- which here means the hook refused a
    negation that genuinely excludes the report."""
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize("glob", ["!*.{ts,tsx}", "!src/**/*.{py,pyi}"], ids=["flat", "recursive"])
def test_a_negated_brace_list_that_does_not_cover_the_path_is_denied(config_dir, glob):
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


def test_a_pathological_brace_pattern_is_denied(config_dir):
    """Expansion is a product of the groups. The hook has a 5s timeout and fails open, so
    a pattern past the bound is refused rather than expanded."""
    assert _denied(_run(_call("Glob", pattern="{a,b}{c,d}{e,f}{g,h}{i,j}.md"), config_dir))


def test_a_pathological_negated_brace_pattern_is_denied(config_dir):
    """The mirror: past the bound, `_covers` cannot prove coverage, which is also a deny."""
    glob = "!{a,b}{c,d}{e,f}{g,h}{i,j}.md"
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    ["!{./docs,zz}/**", "!{docs/,zz}", "!{/docs,zz}/**", "!{a/b,*.md}", "!{md,txt}"],
    ids=["dot-in-brace", "trailing-slash-in-brace", "leading-slash-in-brace", "mixed", "bare"],
)
def test_a_negated_brace_alternative_ripgrep_cannot_honour_is_denied(config_dir, glob):
    """A brace hides a `.` or an empty segment from a guard that runs before expansion:
    `{./docs,zz}` splits into `{.` and `docs,zz}`, neither a bare `.`, and expansion then
    hands `./docs/**` to a `full_match` that drops the `.` and reports a match -- while rg
    hands the report straight over. So the guard runs per alternative, after expansion.

    `{a/b,*.md}` is the anchoring mirror: rg decides anchoring once for the whole glob, so
    the separator in `a/b` anchors `*.md` too and the report three levels down survives.
    """
    assert _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


@pytest.mark.parametrize(
    "glob",
    [
        "!{.,docs}/security/*",
        "!docs/{,security}/*",
        "!docs/{..,security}/*",
        "!{docs,zz}/security/",
    ],
    ids=["dot-alternative", "empty-alternative", "walk-back-alternative", "trailing-slash"],
)
def test_a_negated_brace_with_one_honourable_alternative_is_allowed(config_dir, glob):
    """Skipping an alternative rg cannot honour must not poison the ones it can: each of
    these carries a junk alternative alongside a real exclusion, and rg excludes the report
    under all four."""
    assert not _denied(_run(_call("Grep", pattern="session", glob=glob), config_dir))


def test_a_brace_alternative_naming_an_absolute_tree_is_denied(config_dir):
    """A brace at position zero makes an alternative absolute while the pattern is not, so
    the absolute-vs-relative form mismatch has to be resolved per alternative."""
    pattern = "{/home/you/src/target/docs,zz}/**/*.md"
    assert _denied(_run(_call("Glob", pattern=pattern), config_dir))


def test_a_brace_alternative_that_walks_back_up_is_still_denied(config_dir):
    """`normpath` cannot see into a brace, so each alternative is normalised after
    expansion too -- otherwise the file walks out through the unnormalised one."""
    assert _denied(_run(_call("Glob", pattern="{docs/../docs,zz}/**/*.md"), config_dir))


def test_a_brace_list_against_a_deep_path_is_denied_rather_than_matched(tmp_path):
    """Every alternative is tried against every suffix of the excluded path, so expansion
    multiplies a cost that was linear in that path's depth -- 625 alternatives against a
    2000-segment entry took 8s against a 5s timeout that fails open, which is the leak
    rather than a slow denial. Past the budget the call is refused."""
    deep = "/".join(f"d{i}" for i in range(2000)) + "/rep.md"
    pattern = "{a,b,c,d,e}{a,b,c,d,e}{a,b,c,d,e}{a,b,c,d,e}"
    assert _denied(_run(_call("Glob", pattern=pattern), _listing(tmp_path, deep)))


def test_a_brace_free_pattern_against_a_very_deep_path_is_denied_rather_than_matched(tmp_path):
    """Building those suffixes is quadratic in the entry's depth, so the product ceiling
    does not bound it on its own -- one alternative leaves the depth free. An 8000-segment
    entry exhausted 2GB and raised, and `main` catches that into an allow: the deep path is
    then the way past the hook rather than a slow denial."""
    deep = "/".join(f"directory-number-{i}" for i in range(8000)) + "/rep.md"
    assert _denied(_run(_call("Glob", pattern="src/**/*.py"), _listing(tmp_path, deep)))


def test_an_unbalanced_brace_is_matched_literally(config_dir):
    """`{` is a legal filename character and rg rejects an unclosed group outright, so the
    pattern is left alone rather than guessed at."""
    assert not _denied(_run(_call("Glob", pattern="src/**/*.{ts"), config_dir))
