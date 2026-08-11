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
import yaml

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


LOCK = """
packs:
  asvs:
    version: 5.0.0
  cheatsheets:
    version: "20260805"
  cwe:
    version: "4.20"
"""


def test_record_names_the_digest_and_the_versions_the_lock_declares():
    """This is the claim verify_pin holds the image to, so both halves matter: the
    digest it describes, and what that digest was built from."""
    document = json.loads(_module().record(DIGEST, LOCK, version="0.18.0"))
    assert document["image"] == DIGEST
    assert document["packs"] == {"asvs": "5.0.0", "cheatsheets": "20260805", "cwe": "4.20"}


def test_record_stringifies_versions_yaml_reads_as_numbers():
    """`version: 5.0.0` is a string to YAML but `version: 4.2` is a float, and a
    pack numbered that way would be recorded as `4.2` and compared against kb_info's
    `"4.2"` by substring -- which happens to work, until a float renders as
    `4.20000000001` or `1e+20`. Recording the text sidesteps the whole question."""
    document = json.loads(
        _module().record(DIGEST, "packs:\n  cwe:\n    version: 4.2\n", version="0.18.0")
    )
    assert document["packs"] == {"cwe": "4.2"}


def test_record_refuses_an_image_that_is_not_digest_pinned():
    """A record naming a tag would describe whatever that tag points at today, which
    is the shadowing problem the digest pin exists to remove."""
    with pytest.raises(SystemExit):
        _module().record("ghcr.io/crimson7research/owasp-kb:full", LOCK, version="0.18.0")


def test_record_names_the_version_the_image_reports():
    """doctor compares kb_info's server_version against this. Without it there is
    nothing to compare, which is how a stale server went undiagnosed: the number it
    reported was a legitimate value for a different release."""
    document = json.loads(_module().record(DIGEST, LOCK, version="0.18.0"))
    assert document["server_version"] == "0.18.0"


@pytest.mark.parametrize("bad", ["", "v0.18.0", "latest", "0.18"])
def test_record_refuses_a_version_that_is_not_a_version(bad):
    """The record is what doctor holds the running server to. A record naming an empty
    string or a tag would report every server as mismatched, and a check that always
    fails gets ignored."""
    with pytest.raises(SystemExit):
        _module().record(DIGEST, LOCK, version=bad)


def test_both_scripts_read_the_same_version_literal():
    """pin_image and set_version each carry their own copy of the pattern, because
    scripts/ is not importable under bare pytest. Two copies drift.

    The real file offers no second match, so running both patterns against it cannot
    detect a divergence in anchoring -- only a disagreement about the value. The decoy
    below is what discriminates: an unanchored pattern finds the docstring's mention
    first and reports a version the module does not declare.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("set_version", Path("scripts/set_version.py"))
    set_version = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(set_version)

    text = Path("src/owasp_kb/__init__.py").read_text()
    assert _module().version_of(text) == set_version.current(text)

    decoy = 'x = \'__version__ = "9.9.9"\'\n\n__version__ = "0.17.2"\n'
    assert _module().version_of(decoy) == "0.17.2", (
        "pin_image's pattern matched a version-shaped string that is not the assignment"
    )
    assert set_version.current(decoy) == "0.17.2", (
        "set_version's pattern matched a version-shaped string that is not the assignment"
    )


def test_record_round_trips_the_shipped_file_byte_for_byte():
    """The write is skipped when the content matches, so a formatting difference
    between what this produces and what is committed would show up as a release that
    rewrites the record every time -- or, in review, as a diff nobody asked for."""
    module = _module()
    shipped = Path("plugins/owasp-kb/pinned-packs.json")
    recorded = json.loads(shipped.read_text())
    assert (
        module.record(
            recorded["image"],
            yaml.safe_dump(
                {
                    "packs": {
                        name: {"version": version} for name, version in recorded["packs"].items()
                    }
                }
            ),
            version=recorded["server_version"],
        )
        == shipped.read_text()
    )


def test_the_real_config_carries_a_default_this_script_can_find():
    """Guard against the script and the file it edits drifting apart. Every test
    above runs against TEMPLATE, so all of them keep passing if .mcp.json changes
    shape -- and the release would then fail at the one moment it cannot be
    retried cheaply."""
    text = Path("plugins/owasp-kb/.mcp.json").read_text()
    assert _module().current(text)
