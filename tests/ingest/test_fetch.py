import zipfile

import pytest

from owasp_kb.ingest import fetch as fetch_mod
from owasp_kb.ingest.fetch import fetch_url_pack
from owasp_kb.ingest.lock import LockedPack


def _stub_download(zip_path):
    """A `_download` replacement that copies a pre-built zip instead of hitting
    the network, so these tests never touch the real internet."""

    def _copy(url, target):
        target.write_bytes(zip_path.read_bytes())

    return _copy


def test_fetch_url_pack_unpacks_the_single_member(tmp_path, monkeypatch):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("cwec_v4.20.xml", "<Weakness_Catalog/>")

    monkeypatch.setattr(fetch_mod, "_download", _stub_download(zip_path))

    pack = LockedPack(
        name="cwe",
        type="catalogue",
        version="4.20",
        license="LicenseRef-CWE-TOU",
        url="https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
    )
    out = fetch_url_pack(pack, tmp_path / "dest")
    extracted = out / "cwec_v4.20.xml"
    assert extracted.read_text() == "<Weakness_Catalog/>"


def test_fetch_url_pack_rejects_a_multi_file_archive(tmp_path, monkeypatch):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("one.xml", "a")
        zf.writestr("two.xml", "b")

    monkeypatch.setattr(fetch_mod, "_download", _stub_download(zip_path))

    pack = LockedPack(
        name="cwe",
        type="catalogue",
        version="4.20",
        license="LicenseRef-CWE-TOU",
        url="https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
    )
    with pytest.raises(ValueError, match="found 2"):
        fetch_url_pack(pack, tmp_path / "dest")


def test_fetch_url_pack_without_a_url_raises(tmp_path):
    pack = LockedPack(name="cwe", type="catalogue", version="4.20", license="x")
    with pytest.raises(ValueError, match="cwe"):
        fetch_url_pack(pack, tmp_path)
