# 8. Hybrid retrieval: BM25 + vector, RRF-fused

## Status

Accepted. The specific reasoning that *demoted* vector search from the intended
architecture to a ranking improvement is recorded in ADR
[0002](0002-sqlite-over-postgres-pgvector.md); this ADR records the retrieval
stack that resulted.

## Context

An agent asks the knowledge base questions in its own words — "stop people
brute-forcing logins", "keep my users logged out after they close the tab" —
against a corpus that uses the standard's vocabulary. The original plan assumed
this defeats lexical search: that a paraphrase shares almost no vocabulary with
the document that answers it, so only a real embedding model closes the gap.
On that reasoning, vector search was *the* architecture and BM25 the fallback.

**That claim was asserted without measuring, and it is wrong.** "Brute force"
occurs 34 times across the 120 cheat sheets, and BM25 alone returns the expected
document inside the top 8 for two of the paraphrased test queries — including
the hardest-sounding one, where it ranks the expected document 3rd, beneath
`Transaction_Authorization_Cheat_Sheet` and `Nodejs_Security_Cheat_Sheet`. Real
security documents reuse the exact terminology a real security question uses far
more often than the "no shared vocabulary" framing suggested.

**The real deficiency is ranking, not presence.** Mean rank of the expected
document across the four paraphrased queries: **3.0 under BM25 alone, 2.2 under
hybrid** — a real, worthwhile improvement, but one of degree rather than of
"finds it at all vs. doesn't". Over a separate five-query probe set the same
shape holds: **3.4 lexical / 2.4 vector / 2.0 hybrid**, a 41% mean-rank
improvement over lexical, with hybrid beating BM25 3–1 and vector 2–1 per query.

That reframing is what this whole ADR rests on. It moved vector search from a
capability the product could not work without to an improvement in ordering
among results that were mostly already there — which is what made SQLite +
`sqlite-vec` sufficient (ADR 0002), what made `lite` a legitimate variant rather
than a degraded fallback (ADR [0004](0004-lite-and-full-variants.md)), and what
changed the tests: the paraphrase test now asserts top-3 placement rather than
membership of the top 8, which lexical-only already satisfies.

## Decision

Four choices make up the retrieval stack (`core/retrieval/hybrid.py`,
`core/embed.py`, `core/chunking.py`):

**1. BM25 and vector run independently and are fused with Reciprocal Rank
Fusion, `RRF_K = 60`.** Rejected: replacing BM25 with vector search, and
normalising BM25 scores and cosine distances onto a common scale. RRF avoids
comparing two quantities that are not on a comparable scale and needs no
per-corpus tuning. The precondition for RRF paying at all was measured before
committing to it: over the real corpus, vector ranks the expected document
better on 3 of 5 queries, ties 1, and is worse on 1 ("stop people brute-forcing
logins", rank 6 against BM25's 3). Neither method dominates, which is exactly
the condition under which fusion helps.

**2. `bge-small-en-v1.5` (ONNX), 384 dimensions, CLS pooling, L2 normalisation,
an instruction prefix on queries only.** Rejected: `all-MiniLM-L6-v2`.

**There is no recorded rationale for this choice.** The design spec listed it as
an open item — *"Embedding model choice is provisional: `bge-small-en-v1.5`
(~130 MB) versus `all-MiniLM-L6-v2` (~90 MB). Decide during implementation using
the retrieval test"* — and the comparative retrieval test was never run. MiniLM
appears exactly once in the repository, in that line. The implementing commit
justifies only *how* BGE is used, never *why* BGE. This is the cleanest gap in
the project's decision record and is stated here rather than papered over.

Reconstructing after the fact — and this is reconstruction, not the original
reasoning — the properties that make it fit are: 384 dimensions (~4 MB of vector
data over ~2,400 chunks, small enough to brute-force in under 10 ms and to keep
`sqlite-vec` viable); an ONNX export that runs on CPU with no GPU and no network
call, which the `--network none` container requires; and ~130 MB of weights,
which is a minority of the `full` variant's ~446 MB embedder cost, so the ~40 MB
saved by MiniLM would not have changed the lite/full decision either way. None
of that was written down at the time, and none of it is a measurement.

What *is* pinned, deliberately, is the usage: CLS pooling, L2 normalisation and
the query-only prefix are all required by BGE v1.5 and all degrade retrieval
silently if wrong, so each is asserted in tests rather than trusted.

**3. Chunks are sized to 512 tokens** (`DEFAULT_MAX_TOKENS = 512`), matching the
embedder's `MAX_LENGTH` exactly; the test asserts equality, not `<`. Rejected:
800 (the original) and **400 — which was the filed issue's own recommendation**,
because it cut truncation hardest. Measured against retrieval rank rather than
against truncation alone:

| max_tokens | chunks | truncated | hybrid mean rank |
|---|---|---|---|
| 800 (baseline) | 2,723 | 323 (11.9%) | 2.2 |
| **512 (chosen)** | 2,894 | 133 (4.6%) | **2.2** |
| 400 | 3,059 | 72 (2.4%) | 2.8 (worse) |

At 400, two probe queries regress from rank 2 to rank 3. Smaller chunks give the
embedder less context per vector, so fragmentation costs more than truncation
saves. Matching the window rather than undercutting it removes **61% of the
truncation at zero ranking cost**. Of the 323 chunks truncated at 800, 60 are
more than half inside a fenced code block and genuinely unsplittable; 263 were
ordinary prose. `run_checks` fails the build above
`MAX_TRUNCATED_CHUNK_SHARE = 0.08` — above the measured 4.6% with room for
content drift, well below the 11.9% it exists to catch.

**4. A relevance floor: `MAX_VECTOR_DISTANCE = 0.80`, plus stopword stripping on
the BM25 side.** Rejected: a BM25 score threshold. Off-topic questions were
being answered with confident security guidance — "how do I bake sourdough
bread" returned the XXE prevention cheat sheet — because vector search always
has a nearest neighbour and BM25 matched on stopwords. Vector distance separates
cleanly (relevant 0.52–0.70, noise 0.90–1.03); BM25 scores do not ("sourdough
bread" scored −12.28, better than a real query's third hit, purely on
*how/do/I*), so no BM25 threshold could have worked. A query left with nothing
after stopword stripping matches nothing.

## Consequences

- **The `lite` variant is a real product, not a fallback.** Because the vector
  half buys ranking rather than recall, BM25-only remains a defensible mode; if
  the original paraphrase claim had held, `lite` would have been shipping a
  broken search.
- **`tests/test_retrieval_quality.py` is a permanent regression check on the
  measurement that justified `full`.** If chunking, the embedder or the fusion
  method erodes hybrid's advantage back to parity, the mean-rank comparison is
  what notices. The lite-vs-full comparison reports *rank*, not hit/miss, for
  the same reason the paraphrase claim was wrong: hit/miss would have hidden it.
- **An accepted residual on the relevance floor**, verified rather than assumed:
  "bake" genuinely appears in 2 chunks ("secrets baked into images") and
  "capital" in 1 ("capital letter"), so those queries still return something.
  Suppressing them would require vector agreement, which would break `lite`
  entirely and would also suppress legitimate exact-term lookups — a CWE id, an
  `X-Frame-Options` header — where BM25 is right and the embedder is weak. Two
  weak but judgeable hits is the better trade.
- **The embedding model is the one component with no justification behind it.**
  If it is ever revisited, there is no prior measurement to overturn — only the
  reconstruction above — and the comparative retrieval test the spec called for
  is still the right way to settle it.
- **Chunk size is now coupled to the embedder.** Changing the embedding model to
  one with a different context window means changing `DEFAULT_MAX_TOKENS` with
  it; the equality assertion in the tests is what will force that.
