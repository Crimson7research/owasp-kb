import json
from pathlib import Path

import pytest

from owasp_kb.core.db import connect, is_wal_index
from owasp_kb.ingest.aisvs_guidance import CURATED_GUIDANCE
from owasp_kb.ingest.build import build_index

FIXTURES = Path("tests/fixtures")

# The two upstream links the AISVS fixture chapters carry, plus the curated map.
AISVS_GUIDANCE_TARGETS = {
    "LLM_Prompt_Injection_Prevention_Cheat_Sheet",
    "MCP_Security_Cheat_Sheet",
    *CURATED_GUIDANCE,
}

# The fixture chapters are C2 and C10. The curated map names more, and a curated
# chapter the release lacks stops the build, so each one gets a stub chapter
# holding one requirement.
FIXTURE_AISVS_CHAPTERS = {2, 10}
STUB_AISVS_CHAPTERS = sorted(
    {int(c[1:]) for chapters in CURATED_GUIDANCE.values() for c in chapters}
    - FIXTURE_AISVS_CHAPTERS
)
AISVS_REQUIREMENTS = 5 + len(STUB_AISVS_CHAPTERS)

# Three ASVS-linked fixture sheets plus one stub per AISVS guidance target.
CHEATSHEET_DOCUMENTS = 3 + len(AISVS_GUIDANCE_TARGETS)


def _stub_chapter(number: int) -> str:
    return (
        f"# C{number} Stub Chapter\n\n## C{number}.1 Stub Section\n\n"
        "| # | Description | Level |\n| :--: | --- | :---: |\n"
        f"| **{number}.1.1** | **Verify that** stub {number} holds. | 1 |\n"
    )


# cwe_mapping_sample.json cites CWE-521 and CWE-307, and cwec_sample.xml contains
# neither. That is fine for the per-module fixtures, which never run the integrity
# gate, but a build does: once the catalogue is populated, every mapped id must
# resolve to an entry in it or the build is refused. So this tree maps to two ids
# the fixture catalogue actually defines, keeping the shape the edge-count test
# asserts -- three usable pairs over two requirements, one key that does not
# translate. Written inline rather than as a fifth mapping fixture because it only
# makes sense next to the catalogue it has to agree with.
BUILD_CWE_MAPPING = {
    "v5.0.be-2.1.1": [789],
    "v5.0.be-2.1.2": [789, 664],
    "v5.0.be-9.9.9": [999],
}


@pytest.fixture
def sources(tmp_path):
    """A minimal on-disk source tree in the layout fetch.py produces."""
    asvs = tmp_path / "asvs"
    asvs.mkdir()
    (asvs / "OWASP_ASVS_5.0.0_en.flat.json").write_text(
        (FIXTURES / "asvs_sample.flat.json").read_text(encoding="utf-8")
    )
    (asvs / "v5.0.be_cwe_mapping.json").write_text(json.dumps(BUILD_CWE_MAPPING))
    (asvs / "mapping_v5.0.be_to_v5.0.0.yml").write_text(
        (FIXTURES / "mapping_be_to_500_sample.yml").read_text(encoding="utf-8")
    )
    (asvs / "mapping_v5.0.0_to_v4.0.3.yml").write_text(
        (FIXTURES / "mapping_v5_to_v4_sample.yml").read_text(encoding="utf-8")
    )
    (asvs / "nist.md").write_text((FIXTURES / "nist_sample.md").read_text(encoding="utf-8"))

    masvs = tmp_path / "masvs"
    masvs.mkdir()
    (masvs / "OWASP_MASVS.yaml").write_text(
        (FIXTURES / "masvs_sample.yaml").read_text(encoding="utf-8")
    )

    aisvs = tmp_path / "aisvs"
    aisvs.mkdir()
    for chapter in sorted((FIXTURES / "aisvs").glob("*.md")):
        (aisvs / chapter.name).write_text(chapter.read_text(encoding="utf-8"))
    for number in STUB_AISVS_CHAPTERS:
        (aisvs / f"0x10-C{number:02d}-Stub.md").write_text(_stub_chapter(number))

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
    # Every cheat sheet an AISVS guidance edge can point at, so the integrity
    # gate's dangling-link check passes against the real curated map.
    for name in sorted(AISVS_GUIDANCE_TARGETS):
        (cs / "cheatsheets" / f"{name}.md").write_text(f"# {name}\n\n## Introduction\n\nStub.\n")
    (cs / "IndexASVS.md").write_text((FIXTURES / "IndexASVS_sample.md").read_text(encoding="utf-8"))

    # Named as fetch.py unpacks it: cwec_v<version>.xml, matched by glob so a
    # version bump needs no change here.
    cwe = tmp_path / "cwe"
    cwe.mkdir()
    (cwe / "cwec_v4.20.xml").write_text((FIXTURES / "cwec_sample.xml").read_text(encoding="utf-8"))
    return tmp_path


def _build(sources, out, **kw):
    kw.setdefault("lock_path", "sources.lock.yml")
    kw.setdefault("expected_requirements", {"aisvs": AISVS_REQUIREMENTS, "asvs": 3, "masvs": 4})
    kw.setdefault("with_vectors", False)
    kw.setdefault("check_edge_floors", False)
    return build_index(sources, out, **kw)


def test_build_creates_a_queryable_index(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    report = _build(sources, out)
    assert out.exists()
    assert report.requirements == 3
    # tests/fixtures/masvs_sample.yaml holds 2 groups of 2 controls each -- 4
    # controls total, counted from the fixture rather than hardcoded from memory.
    assert report.masvs_requirements == 4
    assert report.aisvs_requirements == AISVS_REQUIREMENTS
    assert report.cheatsheet_documents == CHEATSHEET_DOCUMENTS
    assert report.integrity_failures == []


def test_build_populates_every_relationship_type(sources, tmp_path):
    """The four owasp_related advertises, plus CWE's own graph.

    Was four, and asserted as an equality, which is what made it worth keeping: a
    build that ingests the catalogue and produces none of its three edge types is
    broken in a way no entry count reveals.
    """
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    conn = connect(out)
    rels = {r[0] for r in conn.execute("SELECT DISTINCT rel FROM links")}
    assert rels == {
        "guidance",
        "cwe",
        "supersedes",
        "nist",
        "cwe_child",
        "cwe_peer",
        "cwe_member",
    }


def test_build_ingests_the_cwe_catalogue(sources, tmp_path):
    """The pack has to be built in, not merely implemented.

    Until build.py dispatched on the lock's cwe entry, catalogue_entries was empty
    in every real build and both CWE integrity checks skipped silently -- the pack
    existed only in its own unit tests.
    """
    out = tmp_path / "kb.sqlite"
    report = _build(sources, out)
    # Measured against cwec_sample.xml: 11 weaknesses and 2 categories. Note the
    # roster in tests/ingest/test_cwe.py names ten weaknesses and omits CWE-400,
    # which the file does contain -- count the fixture, do not read that comment.
    assert report.catalogue_entries == 13

    conn = connect(out)
    entries = conn.execute("SELECT COUNT(*) FROM catalogue_entries").fetchone()[0]
    assert entries == report.catalogue_entries, "the report disagrees with the built index"

    pack = conn.execute("SELECT type, version, license FROM packs WHERE name = 'cwe'").fetchone()
    assert pack is not None, "no cwe pack row; the ingest never ran"
    assert pack["type"] == "catalogue"
    assert pack["version"] == "4.20"
    assert "CWE" in pack["license"], f"license is {pack['license']!r}"


def test_the_catalogue_makes_the_mapping_check_enforceable(sources, tmp_path):
    """The reason the pack is in the index at all.

    An ASVS-mapped CWE id that resolves to nothing is unverifiable, and before the
    catalogue shipped nothing could tell. The check is inert without it, so this
    asserts it now bites: one bad id has to sink the build.
    """
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    conn = connect(out)
    conn.execute(
        "INSERT INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES ('requirement', 'V6.2.1', 'cwe', 'CWE-99999', 'cwe', 'test')"
    )
    conn.commit()
    conn.close()

    from owasp_kb.core.integrity import run_checks

    conn = connect(out)
    failures = run_checks(
        conn,
        expected_requirements={"aisvs": AISVS_REQUIREMENTS, "asvs": 3, "masvs": 4},
        check_edge_floors=False,
    )
    assert any("CWE-99999" in f for f in failures), failures


def test_build_reports_edge_counts(sources, tmp_path):
    report = _build(sources, tmp_path / "kb.sqlite")
    # IndexASVS_sample.md's three, the two AISVS chapter references, and every
    # curated edge -- none of which duplicates an upstream one.
    curated = sum(len(chapters) for chapters in CURATED_GUIDANCE.values())
    assert report.guidance_links == 3 + 2 + curated
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
    # 3 ASVS + 4 MASVS + the AISVS fixture: this counts every checklist pack's
    # rows, not one pack's report field, so it grows with each pack wired in.
    total = served.execute("SELECT COUNT(*) FROM requirements").fetchone()[0]
    assert total == 3 + 4 + AISVS_REQUIREMENTS


def test_build_raises_when_integrity_fails_and_removes_the_file(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    with pytest.raises(RuntimeError, match="integrity"):
        _build(
            sources,
            out,
            expected_requirements={"aisvs": AISVS_REQUIREMENTS, "asvs": 345, "masvs": 4},
        )
    assert not out.exists(), "a failing build must not leave a partial index behind"


def test_a_rejected_catalogue_leaves_no_index_behind(sources, tmp_path):
    """A namespace bump is the case this guards.

    upsert_pack commits the pack row before the entry loops, so a catalogue that
    parses and yields nothing leaves a packs row with zero catalogue_entries.
    ingest_cwe raises on that, which aborts the build -- but the raise used to
    escape with the half-written file still on disk, because only an integrity
    failure removed it. A publishable-looking index beside a traceback is worse
    than either alone.
    """
    (sources / "cwe" / "cwec_v4.20.xml").write_text(
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-99" />'
    )
    out = tmp_path / "kb.sqlite"
    with pytest.raises(ValueError, match="no Weakness or Category"):
        _build(sources, out)
    assert not out.exists(), "a rejected pack must not leave a partial index behind"


def test_main_returns_nonzero_when_a_pack_is_rejected(sources, tmp_path):
    """An unhandled ValueError exits non-zero by traceback, so the exit code alone
    would not have caught this. What it would not do is log an actionable line, and
    it is the one failure mode a fresh upstream release is most likely to produce.
    """
    from owasp_kb.ingest import build as build_mod

    (sources / "cwe" / "cwec_v4.20.xml").write_text(
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-99" />'
    )
    out = tmp_path / "rejected.sqlite"
    rc = build_mod.main(
        [
            "--sources",
            str(sources),
            "--out",
            str(out),
            "--expected-requirements",
            "asvs=3",
            "--expected-requirements",
            "masvs=4",
            "--expected-requirements",
            f"aisvs={AISVS_REQUIREMENTS}",
            "--no-edge-floors",
        ]
    )
    assert rc == 1
    assert not out.exists()


def test_build_is_rerunnable_over_an_existing_file(sources, tmp_path):
    out = tmp_path / "kb.sqlite"
    _build(sources, out)
    report = _build(sources, out)
    assert report.requirements == 3
    assert report.cheatsheet_documents == CHEATSHEET_DOCUMENTS


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
            "asvs=3",
            "--expected-requirements",
            "masvs=4",
            "--expected-requirements",
            f"aisvs={AISVS_REQUIREMENTS}",
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
            "asvs=999",
            "--expected-requirements",
            "masvs=4",
            "--expected-requirements",
            f"aisvs={AISVS_REQUIREMENTS}",
            "--no-edge-floors",
        ]
    )
    assert rc != 0
    assert not out.exists()


def test_main_rejects_a_malformed_expected_requirements_pair(sources, tmp_path):
    """PACK=COUNT is the contract; a value with no '=' or a non-integer count
    must be caught before a build is ever attempted, not surfaced as a traceback."""
    from owasp_kb.ingest import build as build_mod

    out = tmp_path / "malformed.sqlite"
    rc = build_mod.main(
        [
            "--sources",
            str(sources),
            "--out",
            str(out),
            "--expected-requirements",
            "345",
            "--no-edge-floors",
        ]
    )
    assert rc == 1
    assert not out.exists()
