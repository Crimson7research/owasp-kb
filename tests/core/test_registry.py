import pytest

from owasp_kb.core.db import connect
from owasp_kb.core.registry import PACK_TYPES, Pack, get_pack, list_packs, pack_id, upsert_pack
from owasp_kb.core.schema import create_schema


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "kb.sqlite")
    create_schema(c)
    return c


def _pack(name="asvs", type_="checklist", version="5.0.0"):
    return Pack(
        name=name,
        type=type_,
        version=version,
        source_url="https://github.com/OWASP/ASVS",
        commit_sha=None,
        license="CC-BY-SA-4.0",
        fetched_at="2026-07-25T00:00:00Z",
    )


def test_upsert_then_get(conn):
    upsert_pack(conn, _pack())
    got = get_pack(conn, "asvs")
    assert got.version == "5.0.0"
    assert got.type == "checklist"


def test_upsert_is_idempotent_and_updates_version(conn):
    upsert_pack(conn, _pack())
    upsert_pack(conn, _pack(version="5.1.0"))
    assert len(list_packs(conn)) == 1
    assert get_pack(conn, "asvs").version == "5.1.0"


def test_get_unknown_pack_raises_naming_available_packs(conn):
    upsert_pack(conn, _pack())
    upsert_pack(conn, _pack(name="cheatsheets", type_="corpus"))
    with pytest.raises(KeyError) as excinfo:
        get_pack(conn, "asvs5")
    message = str(excinfo.value)
    assert "asvs5" in message
    assert "asvs" in message and "cheatsheets" in message


def test_get_unknown_pack_on_an_empty_registry_still_explains(conn):
    with pytest.raises(KeyError) as excinfo:
        get_pack(conn, "asvs")
    assert "none" in str(excinfo.value).lower()


def test_rejects_unknown_pack_type(conn):
    with pytest.raises(ValueError, match="type"):
        upsert_pack(conn, _pack(type_="graph"))


def test_rejects_unknown_pack_type_before_touching_the_database(conn):
    """Validation must happen in Python, not rely on the CHECK constraint, so the
    error names the valid types rather than surfacing a SQLite message."""
    with pytest.raises(ValueError) as excinfo:
        upsert_pack(conn, _pack(type_="graph"))
    assert "checklist" in str(excinfo.value)
    assert "corpus" in str(excinfo.value)
    assert list_packs(conn) == []


def test_catalogue_is_an_accepted_pack_type():
    """sources.lock.yml declares type: catalogue. Until this passes, ingesting
    the CWE pack fails on the DDL CHECK and again in the registry validator."""
    assert "catalogue" in PACK_TYPES


def test_list_packs_is_sorted_by_name(conn):
    upsert_pack(conn, _pack(name="cheatsheets", type_="corpus"))
    upsert_pack(conn, _pack())
    assert [p.name for p in list_packs(conn)] == ["asvs", "cheatsheets"]


def test_list_packs_on_an_empty_registry_is_empty(conn):
    assert list_packs(conn) == []


def test_round_trip_preserves_every_field(conn):
    original = Pack(
        name="cheatsheets",
        type="corpus",
        version="20260724",
        source_url="https://github.com/OWASP/CheatSheetSeries",
        commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
        license="CC-BY-SA-4.0",
        fetched_at="2026-07-25T12:00:00Z",
    )
    upsert_pack(conn, original)
    assert get_pack(conn, "cheatsheets") == original


def test_pack_id_returns_the_row_id(conn):
    upsert_pack(conn, _pack())
    assert pack_id(conn, "asvs") == 1


def test_pack_id_for_unknown_pack_raises(conn):
    with pytest.raises(KeyError):
        pack_id(conn, "nope")
