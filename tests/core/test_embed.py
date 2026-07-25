import math

import pytest

pytest.importorskip("onnxruntime")

from owasp_kb.core.embed import (  # noqa: E402
    DIM,
    QUERY_PREFIX,
    Embedder,
    model_dir_available,
)

pytestmark = pytest.mark.skipif(
    not model_dir_available(), reason="model not downloaded; run scripts/download_model.py"
)


@pytest.fixture(scope="module")
def embedder():
    return Embedder()


def _dot(a, b):
    return sum(x * y for x, y in zip(a, b, strict=True))


def test_dimension_is_384(embedder):
    assert embedder.dim == DIM == 384


def test_encode_returns_one_vector_per_input(embedder):
    vectors = embedder.encode(["password storage", "session management"])
    assert len(vectors) == 2
    assert all(len(v) == 384 for v in vectors)


def test_vectors_are_l2_normalised(embedder):
    """Required so cosine similarity reduces to a dot product, which is what
    sqlite-vec compares."""
    for vector in embedder.encode(["argon2id", "a much longer sentence about sessions"]):
        assert math.isclose(math.sqrt(sum(x * x for x in vector)), 1.0, abs_tol=1e-3)


def test_query_prefix_is_applied_only_to_queries(embedder):
    as_query = embedder.encode_query("brute force login")
    as_passage = embedder.encode(["brute force login"])[0]
    assert as_query != as_passage, "the asymmetric query prefix must change the embedding"
    assert QUERY_PREFIX.startswith("Represent this sentence")


def test_encode_query_equals_encoding_the_prefixed_text(embedder):
    """Pins that the prefix is applied to the text, not bolted on afterwards."""
    manual = embedder.encode([QUERY_PREFIX + "brute force login"])[0]
    assert embedder.encode_query("brute force login") == pytest.approx(manual, abs=1e-6)


def test_semantic_similarity_beats_lexical_overlap(embedder):
    """The justification for the full variant. If this fails, suspect pooling."""
    query = embedder.encode_query("stop people brute-forcing logins")
    related, unrelated = embedder.encode([
        "Defend against credential stuffing with rate limiting and anti-automation.",
        "Serialize dates in ISO 8601 format for the reporting API.",
    ])
    assert _dot(query, related) > _dot(query, unrelated)


def test_cls_pooling_not_mean_pooling(embedder):
    """BGE uses the CLS token. Mean pooling yields plausible vectors with worse
    retrieval and no error, so pin it by comparing against a mean-pooled vector
    computed from the same model outputs."""
    import numpy as np

    text = "Store passwords with argon2id and a per-user salt."
    encoding = embedder._tokenizer.encode(text)  # noqa: SLF001
    feed = {
        "input_ids": np.array([encoding.ids], dtype=np.int64),
        "attention_mask": np.array([encoding.attention_mask], dtype=np.int64),
    }
    if "token_type_ids" in embedder._input_names:  # noqa: SLF001
        feed["token_type_ids"] = np.array([encoding.type_ids], dtype=np.int64)
    hidden = embedder._session.run(None, feed)[0]  # noqa: SLF001

    cls = hidden[0, 0, :]
    cls = cls / np.linalg.norm(cls)
    mean = hidden[0].mean(axis=0)
    mean = mean / np.linalg.norm(mean)

    produced = np.array(embedder.encode([text])[0])
    assert np.allclose(produced, cls, atol=1e-4), "not CLS-pooled"
    assert not np.allclose(produced, mean, atol=1e-3), "looks mean-pooled"


def test_empty_input_returns_empty_list(embedder):
    assert embedder.encode([]) == []


def test_long_text_is_truncated_not_rejected(embedder):
    """13.6% of real chunks exceed the 512-token limit; they must embed, truncated."""
    vectors = embedder.encode(["word " * 4000])
    assert len(vectors) == 1
    assert len(vectors[0]) == 384


def test_batch_matches_single_encoding(embedder):
    """Padding in a batch must not change a vector."""
    single = embedder.encode(["argon2id"])[0]
    batched = embedder.encode(["argon2id", "a considerably longer unrelated sentence"])[0]
    assert single == pytest.approx(batched, abs=1e-3)


def test_missing_model_raises_actionably(tmp_path):
    from owasp_kb.core.embed import Embedder as E

    with pytest.raises(FileNotFoundError, match="download_model"):
        E(tmp_path / "absent")
