# 7. Python

## Status

Accepted.

## Decision

Build `owasp-kb` in Python (3.13), for both the ingest pipeline and the MCP
server.

## Context

Three alternatives were considered:

- **TypeScript** — the MCP SDK originates in the TypeScript ecosystem and it
  is a natural default for an MCP server. Rejected on its ingest-side tooling:
  this project's real work is markdown parsing with fence-aware heading
  splitting, YAML/JSON mapping-file translation across multiple upstream
  schemas, and ONNX inference — all areas where Python's ecosystem
  (`pyyaml`, `tokenizers`, `onnxruntime`) is materially more mature and more
  directly usable than the TypeScript equivalents, for a project whose
  hardest problems are entirely in ingest, not in serving the protocol.
- **Go or Rust** — either would produce a meaningfully smaller image (no
  Python interpreter or site-packages to ship) and faster cold starts.
  Rejected on two grounds together: ONNX Runtime's bindings for both languages
  are rougher and less battle-tested than the official Python package, which
  matters directly for `core/embed.py`'s correctness (CLS pooling, L2
  normalization, and the BGE query-instruction prefix all have to be exactly
  right, per that module's own docstring, and are easiest to get and keep
  right against the most mature binding available); and both have a
  meaningfully smaller pool of contributors likely to touch a security-content
  ingest pipeline than Python does.

## Consequences

- The devcontainer (`.devcontainer/`) pins **Python 3.13** specifically,
  which is a real constraint discovered during implementation rather than an
  arbitrary choice: the development host runs Python 3.14, where
  `onnxruntime` wheel availability is unreliable at the time of writing. This
  was verified directly rather than assumed — inside the pinned 3.13
  devcontainer, `onnxruntime` 1.28.0, `numpy` 2.5.1, and `tokenizers` 0.23.1
  all resolve and install cleanly together, which is the actual dependency
  set `core/embed.py` needs at runtime for the `full` variant.
- Every image (`docker/Dockerfile`, both `lite` and `full` stages) is built
  `FROM python:3.13-slim`, matching the devcontainer exactly, so "it works in
  the devcontainer" and "it works in the shipped image" stay the same claim.
- The `[dev]`/`[embed]` optional-dependency split in `pyproject.toml` exists
  so the `lite` image's `pip install .` never pulls in `onnxruntime` at all —
  the embedder and its dependencies are opt-in, paid for only by the `full`
  variant that needs them.
