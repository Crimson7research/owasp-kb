"""Unit tests for the release-time image pinning script.

Loaded by path rather than imported as a module: scripts/ is repository tooling and
is not on the import path under bare `pytest`, which is what CI runs. Importing it
as `scripts.pin_image` passes locally and fails in CI -- the defect shape this
repository has already paid for once, a check that was correct about a copy nobody
runs.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

DIGEST = "ghcr.io/crimson7research/owasp-kb@sha256:" + "a" * 64


def _module():
    spec = importlib.util.spec_from_file_location("pin_image", Path("scripts/pin_image.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TEMPLATE = json.dumps(
    {
        "mcpServers": {
            "owasp-kb": {
                "command": "sh",
                "args": ["-c", "exec docker run -i --rm ${OWASP_KB_IMAGE:-owasp-kb:full}"],
            }
        }
    },
    indent=2,
)


def test_current_reads_the_existing_default():
    assert _module().current(TEMPLATE) == "owasp-kb:full"


def test_current_refuses_a_config_with_no_default():
    with pytest.raises(SystemExit):
        _module().current('{"mcpServers": {}}')


def test_rewrite_replaces_the_default_with_the_digest():
    result = _module().rewrite(TEMPLATE, DIGEST)
    assert f"${{OWASP_KB_IMAGE:-{DIGEST}}}" in result
    assert "owasp-kb:full}" not in result


def test_rewrite_leaves_valid_json():
    """The harness reads this file as JSON. A regex rewrite that corrupts it fails
    at plugin load with nothing pointing back here, so the check belongs in the
    rewrite rather than in a reviewer's eye."""
    result = _module().rewrite(TEMPLATE, DIGEST)
    parsed = json.loads(result)
    assert DIGEST in parsed["mcpServers"]["owasp-kb"]["args"][1]


@pytest.mark.parametrize(
    "bad",
    [
        "ghcr.io/crimson7research/owasp-kb:full",
        "owasp-kb:full",
        "ghcr.io/crimson7research/owasp-kb@sha256:tooshort",
        "crimson7research/owasp-kb@sha256:" + "a" * 64,
        "ghcr.io/crimson7research/owasp-kb@sha256:" + "A" * 64,
    ],
)
def test_rewrite_refuses_anything_not_digest_pinned(bad):
    """A tag can be reassigned after the plugin ships, and a bare name resolves to
    Docker Hub. Either one leaves a config that looks pinned and is not, which is
    worse than an obviously unpinned one because nothing looks again.

    The uppercase case is deliberate: docker rejects a non-lowercase digest, so
    accepting one here would produce a config that fails at container start rather
    than at release.
    """
    with pytest.raises(SystemExit):
        _module().rewrite(TEMPLATE, bad)


def test_rewrite_is_idempotent():
    """release.yml can re-run for a re-tagged release. A second pass must produce
    the same file rather than nesting one default inside another."""
    module = _module()
    once = module.rewrite(TEMPLATE, DIGEST)
    assert module.rewrite(once, DIGEST) == once


def test_the_real_config_carries_a_default_this_script_can_find():
    """Guard against the script and the file it edits drifting apart. Every test
    above runs against TEMPLATE, so all of them keep passing if .mcp.json changes
    shape -- and the release would then fail at the one moment it cannot be
    retried cheaply."""
    text = Path("plugins/owasp-kb/.mcp.json").read_text()
    assert _module().current(text)
