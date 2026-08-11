"""Unit tests for the release-time version writer.

Loaded by path rather than imported: scripts/ is repository tooling and is not on the
import path under bare `pytest`, which is what CI runs. Importing it as
`scripts.set_version` passes locally and fails in CI -- the defect shape this
repository has already paid for once, a check that was correct about a copy nobody
runs.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _module():
    spec = importlib.util.spec_from_file_location("set_version", Path("scripts/set_version.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TEMPLATE = '"""Docstring mentioning __version__ = "9.9.9" in prose."""\n\n__version__ = "0.17.2"\n'

QUOTES_ITS_OWN_VERSION = (
    '"""Bumped from 0.17.1 to "0.17.2" for this release."""\n\n__version__ = "0.17.2"\n'
)


def test_current_reads_the_literal():
    assert _module().current(TEMPLATE) == "0.17.2"


def test_current_refuses_a_module_with_no_literal():
    with pytest.raises(SystemExit):
        _module().current('"""No version here."""\n')


@pytest.mark.parametrize("tag", ["v0.18.0", "0.18.0"])
def test_parse_tag_accepts_a_release_tag_with_or_without_the_v(tag):
    """release.yml passes github.ref_name, which carries the v. A human running this
    by hand will type it either way, and the two must not produce different builds."""
    assert _module().parse_tag(tag) == "0.18.0"


@pytest.mark.parametrize("bad", ["v0.18", "0.18.0.1", "latest", "", "v0.18.0rc1", "v-1.0.0"])
def test_parse_tag_refuses_anything_that_is_not_a_release_version(bad):
    """The string this writes is baked into a published image and reported by kb_info
    as that build's identity, so a malformed tag must fail before anything is built
    rather than ship as the version."""
    with pytest.raises(SystemExit):
        _module().parse_tag(bad)


def test_rewrite_replaces_only_the_literal_and_leaves_the_docstring_alone():
    """The module docstring talks about __version__, so an unanchored substitution
    would rewrite prose as well as the assignment."""
    result = _module().rewrite(TEMPLATE, "0.18.0")
    assert '__version__ = "0.18.0"\n' in result
    assert '__version__ = "9.9.9" in prose' in result
    assert '"0.17.2"' not in result


def test_rewrite_changes_nothing_else_in_the_file():
    result = _module().rewrite(TEMPLATE, "0.18.0")
    assert result.replace('"0.18.0"', '"0.17.2"') == TEMPLATE


def test_rewrite_ignores_the_current_version_quoted_in_prose():
    """A mutant that locates the literal by searching for the current value, rather
    than by anchoring to the assignment, passes every other test in this file: the
    decoy above uses a value the module does not declare. With the real value quoted in
    prose, an unanchored search rewrites the sentence and leaves the assignment stale --
    which ships an image reporting the previous release, the exact v0.17.1 failure."""
    result = _module().rewrite(QUOTES_ITS_OWN_VERSION, "0.18.0")
    assert '__version__ = "0.18.0"\n' in result
    assert 'Bumped from 0.17.1 to "0.17.2" for this release.' in result


def test_rewrite_refuses_a_malformed_version():
    """`version` reaches `rewrite` from a caller, not only from `parse_tag` through the
    CLI; a future caller that skips validation would otherwise corrupt the module this
    writes into, since the assignment gets whatever string it is handed."""
    with pytest.raises(SystemExit):
        _module().rewrite(TEMPLATE, "garbage")


def test_rewrite_is_idempotent():
    """release.yml can re-run for a re-tagged release; a second pass must produce the
    same file rather than a second assignment."""
    module = _module()
    once = module.rewrite(TEMPLATE, "0.18.0")
    assert module.rewrite(once, "0.18.0") == once


def test_the_real_module_carries_a_literal_this_script_can_find():
    """Guard against the script and the file it edits drifting apart. Every test above
    runs against TEMPLATE, so all of them keep passing if __init__.py changes shape --
    and the release would then fail at the one moment it cannot be retried cheaply."""
    text = Path("src/owasp_kb/__init__.py").read_text()
    assert _module().current(text)
