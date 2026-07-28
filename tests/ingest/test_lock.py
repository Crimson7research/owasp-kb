import pytest
import yaml

from owasp_kb.ingest.lock import load_lock

LOCK = "sources.lock.yml"


def test_lock_parses_all_three_packs():
    assert set(load_lock(LOCK).packs) == {"asvs", "cheatsheets", "cwe"}


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
        assert pack.type in ("checklist", "corpus", "catalogue")
        assert pack.license in ("CC-BY-SA-4.0", "LicenseRef-CWE-TOU")


def test_release_assets_are_named_exactly_not_globbed():
    """A glob cannot be resolved over plain HTTPS."""
    for pack in load_lock(LOCK).packs.values():
        for asset in pack.assets:
            assert "*" not in asset and "?" not in asset


def test_loading_a_lock_pinning_latest_is_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        yaml.safe_dump(
            {
                "packs": {
                    "asvs": {
                        "type": "checklist",
                        "repo": "OWASP/ASVS",
                        "release": "latest",
                        "version": "5.0.0",
                        "license": "CC-BY-SA-4.0",
                    }
                }
            }
        )
    )
    with pytest.raises(ValueError, match="latest"):
        load_lock(bad)


def test_missing_file_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_lock("nope.yml")


def test_lock_version_matches_the_asset_name(tmp_path):
    """A version bump that forgets the asset filename would fetch the old file."""
    asvs = load_lock(LOCK).packs["asvs"]
    assert any(asvs.version in asset for asset in asvs.assets)


def test_a_pack_can_pin_a_direct_url_instead_of_a_repo(tmp_path):
    """CWE is a zip at a stable URL, not a GitHub release. repo must become
    optional rather than being faked."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        "packs:\n"
        "  cwe:\n"
        "    type: catalogue\n"
        "    version: '4.20'\n"
        "    license: LicenseRef-CWE-TOU\n"
        "    url: https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip\n"
    )
    lock = load_lock(lock_file)
    pack = lock.packs["cwe"]
    assert pack.repo is None
    assert pack.url == "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
    assert pack.version == "4.20"


def test_a_url_pinning_latest_is_rejected(tmp_path):
    """cwec_latest.xml.zip would make a citation resolve to different text as
    MITRE publishes, which defeats the reproducible-citation property the whole
    project rests on."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        "packs:\n"
        "  cwe:\n"
        "    type: catalogue\n"
        "    version: '4.20'\n"
        "    license: LicenseRef-CWE-TOU\n"
        "    url: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip\n"
    )
    with pytest.raises(ValueError, match="latest"):
        load_lock(lock_file)


def test_the_real_lock_pins_cwe_by_version():
    lock = load_lock("sources.lock.yml")
    assert lock.packs["cwe"].version == "4.20"
    assert "4.20" in lock.packs["cwe"].url


def test_a_pack_with_neither_repo_nor_url_is_rejected(tmp_path):
    """Making repo optional for CWE's sake would otherwise let a typo'd key
    through to fetch time, where the error names the wrong cause."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        "packs:\n  broken:\n    type: guidance\n    version: '1.0'\n    license: MIT\n"
    )
    with pytest.raises(ValueError, match="broken"):
        load_lock(lock_file)


def test_a_pack_with_both_repo_and_url_is_rejected(tmp_path):
    """Which one wins at fetch time is ambiguous, so this is caught here rather
    than at whichever fetcher happens to run first."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        "packs:\n"
        "  confused:\n"
        "    type: catalogue\n"
        "    version: '1.0'\n"
        "    license: MIT\n"
        "    repo: some/repo\n"
        "    url: https://example.org/thing.zip\n"
    )
    with pytest.raises(ValueError, match="confused"):
        load_lock(lock_file)
