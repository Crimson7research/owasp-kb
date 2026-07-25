import pytest
import yaml

from owasp_kb.ingest.lock import load_lock

LOCK = "sources.lock.yml"


def test_lock_parses_both_packs():
    assert set(load_lock(LOCK).packs) == {"asvs", "cheatsheets"}


def test_asvs_pins_a_release_not_latest():
    asvs = load_lock(LOCK).packs["asvs"]
    assert asvs.release == "v5.0.0_release"
    assert asvs.release != "latest", "'latest' is the bleeding-edge tag and must not be pinned"


def test_cheatsheets_pins_a_full_commit_sha():
    cs = load_lock(LOCK).packs["cheatsheets"]
    assert cs.commit is not None
    assert len(cs.commit) == 40


def test_every_pack_declares_a_known_type_and_license():
    for pack in load_lock(LOCK).packs.values():
        assert pack.type in ("checklist", "corpus")
        assert pack.license == "CC-BY-SA-4.0"


def test_release_assets_are_named_exactly_not_globbed():
    """A glob cannot be resolved over plain HTTPS."""
    for pack in load_lock(LOCK).packs.values():
        for asset in pack.assets:
            assert "*" not in asset and "?" not in asset


def test_loading_a_lock_pinning_latest_is_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(yaml.safe_dump({"packs": {"asvs": {
        "type": "checklist", "repo": "OWASP/ASVS", "release": "latest",
        "version": "5.0.0", "license": "CC-BY-SA-4.0",
    }}}))
    with pytest.raises(ValueError, match="latest"):
        load_lock(bad)


def test_missing_file_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_lock("nope.yml")


def test_lock_version_matches_the_asset_name(tmp_path):
    """A version bump that forgets the asset filename would fetch the old file."""
    asvs = load_lock(LOCK).packs["asvs"]
    assert any(asvs.version in asset for asset in asvs.assets)
