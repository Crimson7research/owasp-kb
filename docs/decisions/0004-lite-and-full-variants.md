# 4. lite and full variants

## Status

Accepted.

## Context

Hybrid (BM25 + vector) retrieval measurably improves ranking over BM25 alone
(see ADR [0002](0002-sqlite-over-postgres-pgvector.md)), but the embedder that
makes it possible is not free: it adds the ONNX Runtime, the ONNX model
weights, and their Python dependencies to the image, **~446 MB**, taking the
image from 246 MB to 692 MB. Some deployments — a constrained CI runner, a
quick local check, a client environment where 692 MB is itself a friction
point — may reasonably prefer the smaller, lexical-only image and not need
the improvement hybrid buys.

Whether that improvement was even real enough to justify shipping two image
variants (rather than just always paying the 446 MB) was treated as a
question on probation, to be resolved by measurement against the real, fully
built corpus rather than assumed.

## Decision

Ship two image targets from one Dockerfile (`docker/Dockerfile`, `lite` and
`full` stages) with an **identical tool surface** — the same six MCP tools,
the same skills, the same prompts — differing only in which retriever
`Kb.info().retrieval_mode` reports and how it got built. `kb_info` is the
mechanism an agent (or a human) uses to tell which mode is active for a given
running server, rather than the tool set differing between them.

**The probation resolved in `full`'s favour, on measurement:** mean rank
across the four paraphrased test queries goes from 3.0 (lite, BM25 only) to
2.2 (full, hybrid) — better on three of the four queries individually, worse
on one (the "brute-forcing logins" query, where lexical alone already ranks
the expected document 3rd via literal term overlap and RRF fusion pulls the
combined rank to 4th when its two inputs disagree). Three-of-four with a real
mean-rank improvement was judged sufficient to justify shipping `full` as a
real variant rather than an experiment, while `lite` remains a legitimate,
supported choice for the deployments described above rather than a fallback
kept alive only for the cases where `full` cannot run.

**The acceptance bar itself was corrected during this measurement.** An
earlier version of the bar demanded hybrid beat `min(BM25 rank, vector rank)`
on *every* query — i.e., that the fused result never be worse than whichever
single retriever happened to do best on that specific query. That bar is
wrong on its own terms: RRF fusion blends two ranked lists without knowing in
advance which one is more trustworthy for a given query, so when the two
disagree, the fused result necessarily lands *between* them, not always
matching whichever was better. Demanding otherwise asks a blend to behave
like an oracle that already knows which retriever to trust — a property no
fusion method has by construction. The bar was replaced with the one actually
recorded in `tests/test_retrieval_quality.py`: mean rank across the query set
must improve, and per-query rank must land within a generous top-5 window
rather than never regressing relative to the single-retriever best.

## Consequences

- Two images must be built, tagged, smoke-tested, and released together
  (`make build`, `build-lite`/`build-full`; both variants in every CI and
  release workflow) — see [docs/build.md](../build.md).
- A deployer chooses size vs. ranking quality explicitly at install time
  (which image to pull or build) rather than the project making that trade-off
  for them; [docs/install.md](../install.md) documents both paths equally
  rather than treating `lite` as a lesser option.
- The retrieval-quality gate (`tests/test_retrieval_quality.py`) is a
  permanent regression check on the very measurement that justified this
  decision — if a future change to chunking, the embedder, or the fusion
  method erodes hybrid's advantage back toward parity with lexical, that
  test's mean-rank comparison is what will notice.
