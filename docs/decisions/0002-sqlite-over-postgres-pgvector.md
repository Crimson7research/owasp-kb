# 2. SQLite over Postgres + pgvector

## Status

Accepted, superseding an initial preference for Postgres + pgvector.

## Context

The index needs to store ~2,400 chunks, their full text for BM25, and (in the
`full` variant) a 384-dimension vector per chunk for semantic search, then
serve both retrieval modes to an MCP server that a client launches as
`docker run -i --rm --network none <image>`.

The initial preference was Postgres with the `pgvector` extension, justified
at the time by a specific claim about lexical search: that BM25 misses
paraphrased queries entirely, since a query like "keep my users logged out
after they close the tab" shares almost no vocabulary with
`Session_Management_Cheat_Sheet.md`, and only a real embedding model closes
that gap. On that reasoning, SQLite's role would be strictly the fallback
`lite` variant, and Postgres + pgvector the real, intended architecture for
anything hybrid.

**Measured against the actual built index, that claim was wrong.** BM25
alone returns the expected document in the top 8 for two of the four
paraphrased test queries — including the *hardest*-sounding one, "stop people
brute-forcing logins" against `Authentication_Cheat_Sheet`, which BM25 ranks
3rd, not because the query is lexically close to the document's prose but
because the literal string "brute force" occurs 34 times across the corpus.
Paraphrase does not defeat BM25 nearly as reliably as assumed; real security
documents reuse the exact terminology a real security question uses far more
often than the "no shared vocabulary" framing suggested.

**The real deficiency is ranking, not presence.** Across the four paraphrased
queries, mean rank of the expected document is 3.0 under BM25 alone and 2.2
under hybrid (BM25 + vector, RRF-fused) — a real, worthwhile improvement, but
one of *degree*, not of "finds it at all vs. doesn't." That reframing matters
because it changes what the vector half is actually buying: better ordering
among results that were mostly already there, not access to results BM25
could never surface.

With the actual value of vector search reframed as a ranking improvement, the
scale argument against a dedicated vector database follows directly:

- The corpus is **~2,400 chunks**, so the vector data is **~4 MB** at 384
  dimensions (`float32`) — small enough to hold entirely in memory.
- Brute-force cosine distance over that many vectors runs in **under 10 ms**
  (measured) — no approximate index (HNSW, IVFFlat) is needed to make a query
  feel instant.
- `pgvector`'s approximate-index machinery starts paying for itself around
  **10⁶ vectors** — roughly 400x this corpus's current size. Below that,
  brute force is not just adequate, it is simpler and exactly as fast in
  practice.
- The embedding model's inference cost (ONNX Runtime, CPU) is **identical
  either way** — nothing about using Postgres would make embedding faster or
  cheaper, since that cost lives entirely in `core/embed.py`, upstream of
  whichever database stores the result.

## Decision

Use SQLite, with `sqlite-vec` for the vector half of the `full` variant, not
Postgres + pgvector.

The scale argument alone would justify this, but the **decisive factor** is
operational: **Postgres breaks `docker run -i --rm --network none` as a
single self-contained process.** The entire value proposition in
[docs/architecture.md](../architecture.md) and the README's "Runs offline"
section is that an agent gets a knowledge base by running one container with
no network access at all — no second container, no connection string, no
separately-managed database to keep alive alongside the MCP process. Postgres
would require at minimum a second process (in-container or sidecar) and,
practically, real administration (backups, connection pooling, upgrade
paths) that a `--network none` single-binary MCP server has no way to need.
SQLite, opened read-only from a file baked directly into the image, needs
none of that.

## Consequences

- **No hosted, multi-user mode without a migration.** SQLite's single-writer,
  single-file model is the right choice for "one process, one baked index,
  one agent session at a time" — it is not the right choice for a future
  hosted service handling concurrent writers or serving many tenants from one
  running process.
- **`Kb` (`core/kb.py`) is a thin facade specifically so that migration stays
  contained.** Every query the server can answer is a `Kb` method returning
  typed dataclasses, with no SQL or retrieval logic anywhere in `server/` —
  see [docs/architecture.md](../architecture.md). A future Postgres-backed
  `Kb` implementation behind the same interface would not require touching
  `server/tools.py`, `server/prompts.py`, or any skill at all.
- **Postgres remains the right answer for that future hosted deployment**,
  if one is ever built — this decision rejects it for the current
  single-process, offline, per-session model, not as a database in general.
