# Architecture

## Component diagram

Everything upstream of the SQLite file happens once, at build time, offline
from any agent session. Everything downstream happens per query, over stdio,
with no network access.

```
  build time (make build)                      serve time (per agent session)
 ┌─────────────────────────────────────┐       ┌───────────────────────────────┐
 │ sources.lock.yml                     │       │  docker run -i --rm           │
 │   pins ASVS release + CS commit SHA  │       │    --network none owasp-kb    │
 │            │                         │       │            │                  │
 │            v                         │       │            v                  │
 │ ingest/fetch.py  -- downloads -->    │       │  server/app.py (entrypoint)   │
 │   data/asvs/*  data/cheatsheets/*    │       │    opens the baked index      │
 │            │                         │       │    read-only, builds Kb       │
 │            v                         │       │            │                  │
 │ ingest/packs/asvs.py                 │       │            v                  │
 │ ingest/packs/cheatsheets.py           │       │  server/tools.py              │
 │   -> requirements, docs, sections,   │       │    six MCP tool adapters      │
 │      chunks (core/chunking.py)       │       │  server/prompts.py            │
 │            │                         │       │    three MCP prompts          │
 │            v                         │       │            │                  │
 │ ingest/links.py                      │       │            v                  │
 │   -> links edge table                │       │   MCP over stdio              │
 │            │                         │       │            │                  │
 │            v                         │  ==>  │    ┌───────┼────────┐         │
 │ core/embed.py + retrieval/hybrid.py  │  image │    v       v        v         │
 │   (full only) -> chunks_vec          │       │ Claude Code  Codex  OpenCode   │
 │            │                         │       │  (plugin)  (skills) (skills)   │
 │            v                         │       └───────────────────────────────┘
 │ core/integrity.py                    │
 │   refuses to publish a broken index  │
 │            │                         │
 │            v                         │
 │ core/db.py finalize_for_readonly()   │
 │   dist/owasp-kb-{lite,full}.sqlite   │
 └─────────────────────────────────────┘
```

The three agents at the right are Claude Code (via the plugin marketplace),
Codex, and OpenCode (the latter two via `install/*.sh`, which install the
skills and print the MCP config). All three talk to the identical server
binary over stdio; nothing about the server is Claude-Code-specific.

## The four units

- **`ingest/`** — everything that runs at build time and touches the network
  or the filesystem outside the index: `fetch.py` downloads pinned sources per
  `sources.lock.yml`; `lock.py` parses and validates the lock file (and
  refuses `release: latest`); `packs/asvs.py` and `packs/cheatsheets.py` turn
  the two source formats into rows; `links.py` populates the `links` edge
  table from the four upstream mapping files; `build.py` orchestrates all of
  it, runs the integrity checks, and either finalizes the file or deletes it.
  Nothing in `ingest/` is imported by `server/`.

- **`core/`** — the domain model, shared by both ingest and serving. `schema.py`
  holds all DDL. `db.py` is the only place a `sqlite3.Connection` is opened, so
  every pragma is applied consistently. `chunking.py` splits markdown.
  `embed.py` wraps the ONNX embedder. `retrieval/` holds the two retriever
  implementations (`lexical.py`, `hybrid.py`) behind a shared `Protocol`
  (`base.py`). `integrity.py` defines what a shippable index must satisfy.
  `registry.py` is pack CRUD. `kb.py` is the facade described below.

- **`server/`** — the MCP surface: `app.py` is the entrypoint that opens the
  index and wires tools and prompts into a `FastMCP` instance; `tools.py`
  adapts `Kb` methods into six MCP tool callables with trigger-worded
  descriptions (see [docs/discoverability.md](discoverability.md));
  `prompts.py` defines the three MCP prompts.

- **`plugin/`** (`plugins/owasp-kb/`) — the Claude Code plugin: the manifest,
  the `.mcp.json` that launches the container, and the four skills. Consumed
  directly by Claude Code via the marketplace, and indirectly by Codex/OpenCode
  via the install scripts, which copy the same skill directories elsewhere.

**`Kb` is the facade.** Every query the server can answer — search, outline,
get, checklist, related, info — is a method on `owasp_kb.core.kb.Kb`, taking a
`sqlite3.Connection` and returning typed dataclasses (`core/models.py`).
`server/tools.py` does nothing but call a `Kb` method, catch its exceptions,
and reshape the result into a JSON-able dict. **There is no retrieval logic in
`server/`** — no SQL, no ranking, no fusion. That split exists so the
retrieval quality tests (`tests/test_retrieval_quality.py`) exercise `Kb`
directly against a real built index, without an MCP client in the loop, and so
a change to how search ranks results can never require touching the server.

## Pack registry

A **pack** is one ingested knowledge base, recorded in the `packs` table with
a `type` of either:

- **`checklist`** — an enumerable, leveled requirement set. Currently only
  `asvs`. Supports `owasp_checklist` (enumerate by chapter/section/id/level)
  in addition to the corpus-navigation tools below.
- **`corpus`** — a document collection with no per-item structure beyond
  headings. Currently only `cheatsheets`. Supports `owasp_search`,
  `owasp_outline`, `owasp_get` — not `owasp_checklist`, which raises
  `ValueError` naming the tools that do apply if called against a corpus pack.

`owasp_related` and `owasp_search` work across both types uniformly, because
both ultimately resolve to rows in `chunks`. See
[docs/kb-packs.md](kb-packs.md) for the full contract and how to add one.

## Schema

```
packs         (id, name UNIQUE, type CHECK IN ('checklist','corpus'), version,
               source_url, commit_sha, license, fetched_at)
docs          (id, pack_id -> packs, doc_key, title, source_path, source_url;
               UNIQUE(pack_id, doc_key))
sections      (id, doc_id -> docs, anchor, heading_path, ord, depth;
               UNIQUE(doc_id, anchor))
chunks        (id, section_id -> sections, text, token_est)
chunks_fts    FTS5 virtual table, external-content over chunks, porter+unicode61
chunks_vec    vec0 virtual table (full builds only): chunk_id -> FLOAT[384]
requirements  (id, pack_id -> packs, req_id, chapter_id, chapter_name,
               section_id, section_name, text, level, chunk_id -> chunks;
               UNIQUE(pack_id, req_id))
links         (from_kind, from_id, to_kind, to_id, rel, source;
               PRIMARY KEY(from_kind, from_id, to_kind, to_id, rel))
```

`chunks_fts` is kept in sync with `chunks` by triggers (`chunks_ai`/`ad`/`au`)
rather than rebuilt, so ingest never has to remember to reindex. `requirements`
carries its own `chunk_id` — every requirement is exactly one chunk — so
`owasp_search` can return a requirement hit through the same `chunks` join
every corpus hit goes through (see `HIT_SQL` in `core/retrieval/base.py`).

## The `links` edge table

Every cross-reference the server can traverse — ASVS-to-cheat-sheet,
requirement-to-CWE, requirement-to-NIST, v5-to-v4 — is one row in `links`,
keyed by `(from_kind, from_id, to_kind, to_id, rel)`. Four `rel` values exist:

| `rel` | From → To | Source file |
|---|---|---|
| `guidance` | ASVS section/chapter → cheat sheet `doc_key` | `IndexASVS.md` |
| `cwe` | requirement → `CWE-nnn` | `v5.0.be_cwe_mapping.json`, translated through `mapping_v5.0.be_to_v5.0.0.yml` |
| `supersedes` | requirement → its v4.0.3 predecessor | `mapping_v5.0.0_to_v4.0.3.yml` |
| `nist` | requirement → a NIST SP 800-63B section | `nist.md`, composed through `supersedes` |

Exact edge counts, per-source caveats, and why each composition step is
necessary are in [docs/build.md](build.md#mapping-coverage). `owasp_related`
rolls a requirement's id up to its section and chapter before querying, because
`guidance` edges are recorded against sections while agents ask about
requirements — see `Kb.related` in `core/kb.py`.

## Chunking rules

Markdown is split at H2/H3 boundaries (`SPLIT_DEPTHS = (2, 3)`) by
`core/chunking.py`, carrying the full heading path (e.g. `"Authentication
Cheat Sheet > Password Storage"`) with every chunk so a hit can cite exactly
where it came from. Rules that matter beyond the obvious:

- **Fence-aware.** A `#`-prefixed line inside a ` ``` ` or `~~~` fence is code,
  not a heading, and is never split on. `integrity.py` additionally rejects
  any chunk with an unbalanced fence count as a build-time invariant.
- **Anchors are GitHub-slug-compatible** (`slugify`) and disambiguated in
  document order the way GitHub does (`-1`, `-2`, ...) when two headings
  collapse to the same slug — measured, 9 real documents collide, one with 12
  sections all slugifying to `do`. Anchors must be unique because
  `sections.anchor` carries `UNIQUE(doc_id, anchor)`; a collision would
  silently merge two subsections' content under one citation.
- **Oversized sections are split further** on blank-line boundaries, never
  inside a fence, targeting `DEFAULT_MAX_TOKENS = 800` (a `len(text)//4`
  estimate, not a real tokenizer count — cheap and sufficient for a split
  threshold). This is why 13.6% of chunks still exceed the embedder's real
  512-token limit: the worst offender is 97% a single fenced code block,
  which cannot be split further without breaking the fence invariant above.
  BM25 has no length limit and covers what the embedder cannot see.
- **ASVS requirements are not split at all** — each is ingested as exactly one
  chunk (`packs/asvs.py`), since a requirement is already a single sentence
  plus its chapter/section heading.

## Serving details

- **The index is opened `read_only=True`.** `core/db.connect(..., read_only=True)`
  opens with `mode=ro&immutable=1` rather than merely `mode=ro`: `immutable=1`
  tells SQLite to skip locking and change detection entirely, which is both
  required (the image bakes the index into a root-owned, non-writable
  directory) and only safe because the build already finalized the file out of
  WAL mode — see `core/db.finalize_for_readonly` and ADR
  `docs/decisions/0003-baked-index-not-runtime-fetch.md`.
- **Server logging goes to stderr, never stdout.** `server/app.py` configures
  `logging.basicConfig(..., stream=sys.stderr)` explicitly, because stdout is
  the MCP stdio transport — anything else written there corrupts every
  message after it. This is also the first thing to check if a server process
  starts and then immediately exits (see the troubleshooting table in
  [docs/install.md](install.md)).
