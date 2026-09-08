import pytest
import yaml

from owasp_kb.core.registry import PACK_TYPES
from owasp_kb.ingest.lock import load_lock

LOCK = "sources.lock.yml"


def _lock_yaml(packs: dict) -> str:
    """Render a ``packs:`` mapping the way sources.lock.yml is structured, so
    test fixtures are built the same way as the real file rather than as
    hand-typed strings that can drift from valid YAML unnoticed."""
    return yaml.safe_dump({"packs": packs})


def test_lock_parses_all_four_packs():
    assert set(load_lock(LOCK).packs) == {"asvs", "cheatsheets", "cwe", "masvs"}


def test_masvs_pins_a_release_and_its_machine_readable_asset():
    """The YAML asset is the only ingestable form: the pdf and epub are not.

    version comes from here and never from the document -- the repo-root copy of
    OWASP_MASVS.yaml carries the placeholder `metadata.version: vx.x.x`.
    """
    masvs = load_lock(LOCK).packs["masvs"]
    assert masvs.type == "checklist"
    assert masvs.release == "v2.1.0"
    assert masvs.version == "2.1.0"
    assert masvs.license == "CC-BY-SA-4.0"
    assert masvs.assets == ["OWASP_MASVS.yaml"]
    assert masvs.commit is None


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
        assert pack.type in PACK_TYPES
        assert pack.license in ("CC-BY-SA-4.0", "LicenseRef-CWE-TOU")


def test_release_assets_are_named_exactly_not_globbed():
    """A glob cannot be resolved over plain HTTPS."""
    for pack in load_lock(LOCK).packs.values():
        for asset in pack.assets:
            assert "*" not in asset and "?" not in asset


def test_loading_a_lock_pinning_latest_is_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        _lock_yaml(
            {
                "asvs": {
                    "type": "checklist",
                    "repo": "OWASP/ASVS",
                    "release": "latest",
                    "version": "5.0.0",
                    "license": "CC-BY-SA-4.0",
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
        _lock_yaml(
            {
                "cwe": {
                    "type": "catalogue",
                    "version": "4.20",
                    "license": "LicenseRef-CWE-TOU",
                    "url": "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
                }
            }
        )
    )
    lock = load_lock(lock_file)
    pack = lock.packs["cwe"]
    assert pack.repo is None
    assert pack.url == "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
    assert pack.version == "4.20"


LATEST_GUARD_URL_CASES = [
    # A "/latest/" directory moves as upstream republishes into it, so a
    # pinned-looking filename underneath it is still not pinned.
    ("https://example.com/latest/cwec_v4.20.xml.zip", True),
    # Already covered before the fix; kept so path-scoping cannot regress it.
    ("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", True),
    # A host containing "latest" has no bearing on reproducibility.
    ("https://latest-cdn.example.com/cwec_v4.20.xml.zip", False),
]


@pytest.mark.parametrize("url,rejected", LATEST_GUARD_URL_CASES)
def test_the_latest_guard_is_scoped_to_the_url_path(tmp_path, url, rejected):
    """Matching the filename alone would accept a /latest/ directory holding a
    pinned-looking filename; matching the whole url would reject a host like
    latest-cdn.example.com that has no bearing on reproducibility. Only the
    path avoids both holes."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        _lock_yaml(
            {
                "cwe": {
                    "type": "catalogue",
                    "version": "4.20",
                    "license": "LicenseRef-CWE-TOU",
                    "url": url,
                }
            }
        )
    )
    if rejected:
        with pytest.raises(ValueError, match="latest"):
            load_lock(lock_file)
    else:
        assert load_lock(lock_file).packs["cwe"].url == url


def test_the_real_lock_pins_cwe_by_version():
    lock = load_lock("sources.lock.yml")
    assert lock.packs["cwe"].version == "4.20"
    assert "4.20" in lock.packs["cwe"].url


def test_a_pack_with_neither_repo_nor_url_is_rejected(tmp_path):
    """Making repo optional for CWE's sake would otherwise let a typo'd key
    through to fetch time, where the error names the wrong cause."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        _lock_yaml({"broken": {"type": "guidance", "version": "1.0", "license": "MIT"}})
    )
    with pytest.raises(ValueError, match="broken"):
        load_lock(lock_file)


def test_a_pack_with_both_repo_and_url_is_rejected(tmp_path):
    """Which one wins at fetch time is ambiguous, so this is caught here rather
    than at whichever fetcher happens to run first."""
    lock_file = tmp_path / "sources.lock.yml"
    lock_file.write_text(
        _lock_yaml(
            {
                "confused": {
                    "type": "catalogue",
                    "version": "1.0",
                    "license": "MIT",
                    "repo": "some/repo",
                    "url": "https://example.org/thing.zip",
                }
            }
        )
    )
    with pytest.raises(ValueError, match="confused"):
        load_lock(lock_file)
