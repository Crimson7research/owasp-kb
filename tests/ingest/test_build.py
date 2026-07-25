from pathlib import Path

import pytest

from owasp_kb.core.db import connect, is_wal_index
from owasp_kb.ingest.build import build_index

FIXTURES = Path("tests/fixtures")


@pytest.fixture
def sources(tmp_path):
    """A minimal on-disk source tree in the layout fetch.py produces."""
    asvs = tmp_path / "asvs"
    asvs.mkdir()
    (asvs / "OWASP_ASVS_5.0.0_en.flat.json").write_text(
        (FIXTURES / "asvs_sample.flat.json").read_text(encoding="utf-8")
    )
    (asvs / "v5.0.be_cwe_mapping.json").write_text(
        (FIXTURES / "cwe_mapping_sample.json").read_text(encoding="utf-8")
    )
    (asvs / "mapping_v5.0.be_to_v5.0.0.yml").write_text(
        (FIXTURES / "mapping_be_to_500_sample.yml").read_text(encoding="utf-8")
    )
    (asvs / "mapping_v5.0.0_to_v4.0.3.yml").write_text(
        (FIXTURES / "mapping_v5_to_v4_sample.yml").read_text(encoding="utf-8")
    )
    (asvs / "nist.md").write_text((FIXTURES / "nist_sample.md").read_text(encoding="utf-8"))

    cs = tmp_path / "cheatsheets"
    (cs / "cheatsheets").mkdir(parents=True)
    for name in (
        "Authentication_Cheat_Sheet.md",
        "Credential_Stuffing_Prevention_Cheat_Sheet.md",
        "Session_Management_Cheat_Sheet.md",
    ):
        (cs / "cheatsheets" / name).write_text(
            (FIXTURES / "cheatsheets" / name).read_text(encoding="utf-8")
        )
    (cs / "IndexASVS.md").write_text((FIXTURES / "IndexASVS_sample.md").read_text(encoding="utf-8"))
    return tmp_path


def _build(sources, out, **kw):
    kw.setdefault("lock_path", "sources.lock.yml")
    kw.setdefault("expected_requirements", 3)
    kw.setdefault("with_vectors", False)
    kw.setdefault("check_edge_floors", False)
    return build_index(sources, out, **kw)


def test_build_creates_a_queryable_index(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    report = _build(sources, out)
    assert out.exists()
    assert report.requirements == 3
    assert report.documents == 3
    assert report.integrity_failures == []


def test_build_populates_all_four_relationship_types(sources, tmp_path):
    """owasp_related advertises four; a build producing fewer is broken."""
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    conn = connect(out)
    rels = {r[0] for r in conn.execute("SELECT DISTINCT rel FROM links")}
    assert rels == {"guidance", "cwe", "supersedes", "nist"}


def test_build_reports_edge_counts(sources, tmp_path):
    report = _build(sources, tmp_path / "kb.sqlite")
    assert report.guidance_links == 3
    assert report.cwe_links == 3
    assert report.cwe_dropped == 1
    assert report.supersedes_links >= 3
    assert report.nist_links >= 1


def test_nist_runs_after_supersedes(sources, tmp_path):
    """NIST composes over supersedes edges; reversed order yields zero."""
    report = _build(sources, tmp_path / "kb.sqlite")
    assert report.nist_links > 0, "nist ran before supersedes, or the join broke"


def test_build_finalizes_the_index_for_readonly_serving(sources, tmp_path):
    """WAL persists in the header and cannot be opened from the image's
    non-writable directory. This only fails at container runtime, so it is
    asserted here."""
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    assert not is_wal_index(out)
    served = connect(out, read_only=True)
    assert served.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 3


def test_build_raises_when_integrity_fails_and_removes_the_file(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    with pytest.raises(RuntimeError, match="integrity"):
        _build(sources, out, expected_requirements=345)
    assert not out.exists(), "a failing build must not leave a partial index behind"


def test_build_is_rerunnable_over_an_existing_file(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    report = _build(sources, out)
    assert report.requirements == 3
    assert report.documents == 3


def test_build_missing_source_raises_actionably(tmp_path):
    with pytest.raises(FileNotFoundError) as excinfo:
        _build(tmp_path / "absent", tmp_path / "kb.sqlite")
    assert "flat.json" in str(excinfo.value) or "absent" in str(excinfo.value)


def test_report_counts_chunks(sources, tmp_path):
    report = _build(sources, tmp_path / "kb.sqlite")
    assert report.chunks > 0


def test_main_returns_zero_on_success(sources, tmp_path):
    from owasp_kb.ingest import build as build_mod

    out = tmp_path / "cli.sqlite"
    rc = build_mod.main(
        [
            "--sources",
            str(sources),
            "--out",
            str(out),
            "--expected-requirements",
            "3",
            "--no-edge-floors",
        ]
    )
    assert rc == 0
    assert out.exists()


def test_main_returns_nonzero_when_integrity_fails(sources, tmp_path):
    from owasp_kb.ingest import build as build_mod

    out = tmp_path / "bad.sqlite"
    rc = build_mod.main(
        [
            "--sources",
            str(sources),
            "--out",
            str(out),
            "--expected-requirements",
            "999",
            "--no-edge-floors",
        ]
    )
    assert rc != 0
    assert not out.exists()
