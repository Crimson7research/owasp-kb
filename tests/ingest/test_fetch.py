import re
import zipfile

import pytest

from owasp_kb.ingest import fetch as fetch_mod
from owasp_kb.ingest.fetch import fetch_url_pack
from owasp_kb.ingest.lock import LockedPack


@pytest.fixture
def cwe_pack():
    return LockedPack(
        name="cwe",
        type="catalogue",
        version="4.20",
        license="LicenseRef-CWE-TOU",
        url="https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
    )


def _stub_download(source_path):
    """A `_download` replacement that copies a pre-built file into place instead
    of hitting the network, so these tests never touch the real internet."""

    def _copy(url, target):
        target.write_bytes(source_path.read_bytes())

    return _copy


def test_fetch_url_pack_unpacks_the_single_member(tmp_path, monkeypatch, cwe_pack):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("cwec_v4.20.xml", "<Weakness_Catalog/>")
    monkeypatch.setattr(fetch_mod, "_download", _stub_download(zip_path))

    out = fetch_url_pack(cwe_pack, tmp_path / "dest")
    extracted = out / "cwec_v4.20.xml"
    assert extracted.read_text() == "<Weakness_Catalog/>"


def test_fetch_url_pack_rejects_a_multi_file_archive(tmp_path, monkeypatch, cwe_pack):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("one.xml", "a")
        zf.writestr("two.xml", "b")
    monkeypatch.setattr(fetch_mod, "_download", _stub_download(zip_path))

    with pytest.raises(ValueError, match="found 2"):
        fetch_url_pack(cwe_pack, tmp_path / "dest")


def test_fetch_url_pack_rejects_a_corrupt_download(tmp_path, monkeypatch, cwe_pack):
    """A truncated transfer or an HTML error page saved as if it were the zip is
    exactly the case this needs to name, not raise a bare BadZipFile."""
    not_a_zip = tmp_path / "not_a_zip"
    not_a_zip.write_text("<html>502 Bad Gateway</html>")
    monkeypatch.setattr(fetch_mod, "_download", _stub_download(not_a_zip))

    with pytest.raises(ValueError, match=re.escape(cwe_pack.url)):
        fetch_url_pack(cwe_pack, tmp_path / "dest")


def test_fetch_url_pack_without_a_url_raises(tmp_path):
    pack = LockedPack(name="cwe", type="catalogue", version="4.20", license="x")
    with pytest.raises(ValueError, match="cwe"):
        fetch_url_pack(pack, tmp_path)
