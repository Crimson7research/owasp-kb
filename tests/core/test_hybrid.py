import pytest

from owasp_kb.core.db import connect, vec_available
from owasp_kb.core.embed import model_dir_available
from owasp_kb.core.retrieval import build_retriever
from owasp_kb.core.retrieval.hybrid import rrf_fuse, serialize_f32
from owasp_kb.core.schema import create_schema
from owasp_kb.ingest.packs.asvs import ingest_asvs
from owasp_kb.ingest.packs.cheatsheets import ingest_cheatsheets

needs_model = pytest.mark.skipif(not model_dir_available(), reason="model not downloaded")


def test_rrf_fuse_prefers_a_consistently_good_item_over_a_polarising_one():
    """Consistency wins only once the spread is wide enough.

    1/x is convex, so over a narrow spread the extremes beat the middle: for
    [[a,b,c],[c,b,a]] the items ranked 1st-and-3rd score 124/3843 against b's
    1/31 at k=60, and that holds for every k > 0. An earlier version of this
    test asserted b came first, which is not a property RRF has. The real
    guarantee is that an item ranked well by both lists beats one that a single
    list buries.
    """
    fused = rrf_fuse(
        [["polarising", "steady"], ["steady"] + [f"x{i}" for i in range(18)] + ["polarising"]], k=60
    )
    assert fused[0] == "steady"


def test_rrf_fuse_extremes_beat_the_middle_over_a_narrow_spread():
    """Pins the convexity behaviour above so it is documented, not a surprise."""
    fused = rrf_fuse([["a", "b", "c"], ["c", "b", "a"]], k=60)
    assert fused[-1] == "b"


def test_rrf_fuse_includes_items_from_a_single_list():
    assert set(rrf_fuse([["a"], ["b"]], k=60)) == {"a", "b"}


def test_rrf_fuse_of_empty_lists_is_empty():
    assert rrf_fuse([[], []], k=60) == []


def test_rrf_fuse_is_deterministic_on_ties():
    """Equal scores must break by first appearance, not dict ordering."""
    assert rrf_fuse([["a", "b"], ["a", "b"]], k=60) == ["a", "b"]


def test_rrf_fuse_beats_a_single_bad_ranking():
    """An item ranked well by one list and poorly by the other still surfaces."""
    fused = rrf_fuse([["x", "y", "z", "target"], ["target", "z", "y", "x"]], k=60)
    assert fused.index("target") < fused.index("y")


def test_serialize_f32_round_trips_length():
    assert len(serialize_f32([0.0] * 384)) == 384 * 4


def _index(tmp_path, *, with_vectors: bool):
    path = tmp_path / "kb.sqlite"
    conn = connect(path, load_vec=with_vectors)
    create_schema(conn)
    ingest_asvs(
        conn, "tests/fixtures/asvs_sample.flat.json", version="5.0.0", license="CC-BY-SA-4.0"
    )
    ingest_cheatsheets(
        conn,
        "tests/fixtures/cheatsheets",
        version="20260724",
        commit_sha="7d1c2d3daf632206e8f2c685214c699ff8f11938",
        license="CC-BY-SA-4.0",
    )
    return conn, path


def test_build_retriever_degrades_to_lexical_without_the_extension(tmp_path):
    conn, _ = _index(tmp_path, with_vectors=False)
    assert build_retriever(conn).mode == "lexical"


def test_build_retriever_degrades_to_lexical_when_no_vectors_indexed(tmp_path):
    conn, _ = _index(tmp_path, with_vectors=True)
    assert vec_available(conn)
    assert build_retriever(conn).mode == "lexical"


def test_degradation_is_logged_not_silent(tmp_path, caplog):
    conn, _ = _index(tmp_path, with_vectors=False)
    with caplog.at_level("INFO"):
        build_retriever(conn)
    assert any("lexical" in r.message.lower() for r in caplog.records)


@needs_model
def test_hybrid_mode_selected_when_vectors_present(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    assert index_vectors(conn, Embedder()) > 0
    assert build_retriever(conn).mode == "hybrid"


@needs_model
def test_index_vectors_is_idempotent(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    embedder = Embedder()
    first = index_vectors(conn, embedder)
    second = index_vectors(conn, embedder)
    assert first == second
    assert conn.execute("SELECT COUNT(*) FROM chunks_vec").fetchone()[0] == first


@needs_model
def test_hybrid_returns_citable_hits(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    hits = build_retriever(conn).search("argon2id", limit=5)
    assert hits
    assert all(h.citation and "None" not in h.citation for h in hits)


@needs_model
def test_hybrid_respects_pack_and_level_filters(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    retriever = build_retriever(conn)
    assert {h.pack for h in retriever.search("password", pack="cheatsheets", limit=10)} == {
        "cheatsheets"
    }
    level_hits = retriever.search("password", pack="asvs", level="1", limit=10)
    assert level_hits
    assert all(h.req_id == "V6.2.1" for h in level_hits)


@needs_model
def test_hybrid_unknown_pack_raises(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    with pytest.raises(KeyError):
        build_retriever(conn).search("password", pack="nope", limit=5)


@needs_model
def test_hybrid_scores_are_descending(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    scores = [h.score for h in build_retriever(conn).search("password", limit=10)]
    assert scores == sorted(scores, reverse=True)


@needs_model
def test_vector_results_beyond_the_distance_floor_are_rejected(tmp_path):
    """Without a floor, vector search always returns a nearest neighbour, so an
    off-topic question came back with confident-looking security guidance."""
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    assert build_retriever(conn).search("how do I bake sourdough bread", limit=5) == []


@needs_model
def test_hybrid_finds_a_paraphrase_lexical_ranks_poorly(tmp_path):
    from owasp_kb.core.embed import Embedder
    from owasp_kb.core.retrieval.hybrid import index_vectors

    conn, _ = _index(tmp_path, with_vectors=True)
    index_vectors(conn, Embedder())
    hits = build_retriever(conn).search(
        "stop people brute-forcing logins", pack="cheatsheets", limit=3
    )
    assert "Authentication_Cheat_Sheet" in {h.doc_key for h in hits}
