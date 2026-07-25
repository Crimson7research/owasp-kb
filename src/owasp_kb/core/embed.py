"""BGE-small-en-v1.5 embeddings via ONNX Runtime.

BGE v1.5 requires CLS pooling, L2 normalisation, and an instruction prefix on
queries only. All three matter for retrieval quality and none of them fail
loudly if wrong, so each is pinned here and asserted in tests.
"""

from __future__ import annotations

import os
from pathlib import Path

QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
DEFAULT_MODEL_DIR = Path(os.environ.get("OWASP_KB_MODEL_DIR", "models/bge-small-en-v1.5"))
DIM = 384
MAX_LENGTH = 512


def model_dir_available(path: Path | None = None) -> bool:
    directory = path or DEFAULT_MODEL_DIR
    return (directory / "model.onnx").exists() and (directory / "tokenizer.json").exists()


class Embedder:
    """Encodes text to unit-length 384-dimension vectors."""

    def __init__(self, model_dir: Path | None = None) -> None:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self._np = np
        directory = Path(model_dir) if model_dir is not None else DEFAULT_MODEL_DIR
        if not model_dir_available(directory):
            raise FileNotFoundError(
                f"no ONNX model under {directory}; run scripts/download_model.py"
            )
        self._tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=MAX_LENGTH)
        self._tokenizer.enable_padding()
        self._session = ort.InferenceSession(
            str(directory / "model.onnx"), providers=["CPUExecutionProvider"]
        )
        self._input_names = {i.name for i in self._session.get_inputs()}

    @property
    def dim(self) -> int:
        return DIM

    def encode(self, texts: list[str]) -> list[list[float]]:
        """Embed passages. Do not use for queries — see encode_query."""
        if not texts:
            return []
        np = self._np
        encodings = self._tokenizer.encode_batch(texts)
        feed = {
            "input_ids": np.array([e.ids for e in encodings], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in encodings], dtype=np.int64),
        }
        if "token_type_ids" in self._input_names:
            feed["token_type_ids"] = np.array([e.type_ids for e in encodings], dtype=np.int64)
        hidden = self._session.run(None, feed)[0]
        cls = hidden[:, 0, :]  # BGE uses the CLS token, not mean pooling.
        norms = np.linalg.norm(cls, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return (cls / norms).astype(np.float32).tolist()

    def encode_query(self, query: str) -> list[float]:
        """Embed a search query, applying BGE's asymmetric instruction prefix."""
        return self.encode([QUERY_PREFIX + query])[0]
