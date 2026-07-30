# Architecture

## Component diagram

Everything upstream of the SQLite file happens once, at build time, offline
from any agent session. Everything downstream happens per query, over stdio,
with no network access.

```
  build time (make build)                      serve time (per agent session)
 ┌─────────────────────────────────────┐       ┌───────────────────────────────┐
 │ sources.lock.yml                     │       │  docker run -i --rm           │
 │   pins ASVS + CWE releases, CS SHA   │       │    --network none owasp-kb    │
 │            │                         │       │            │                  │
 │            v                         │       │            v                  │
 │ ingest/fetch.py  -- downloads -->    │       │  server/app.py (entrypoint)   │
 │   data/{asvs,cheatsheets,cwe}/*      │       │    opens the baked index      │
 │            │                         │       │    read-only, builds Kb       │
 │            v                         │       │            │                  │
 │ ingest/packs/{asvs,cheatsheets,      │       │            v                  │
 │               cwe}.py                │       │  server/tools.py              │
 │   -> requirements, catalogue_entries,│       │    ten MCP tool adapters      │
 │      docs, sections, chunks          │       │                               │
 │      (core/chunking.py)              │       │  server/prompts.py            │
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
  refuses `release: latest`); `packs/asvs.py`, `packs/cheatsheets.py` and
  `packs/cwe.py` turn the three source formats into rows; `links.py` populates
  the `links` edge table from the four upstream mapping files, and `packs/cwe.py`
  writes CWE's own three graph rels directly; `build.py` orchestrates all of
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
  adapts `Kb` methods into ten MCP tool callables with trigger-worded
  descriptions (see [docs/discoverability.md](discoverability.md));
  `prompts.py` defines the three MCP prompts.

- **`plugin/`** (`plugins/owasp-kb/`) — the Claude Code plugin: the manifest,
  the `.mcp.json` that launches the container, the four skills, and the five
  agent definitions the two assessment skills dispatch (see [The assessment
  layer](#the-assessment-layer)). Consumed directly by Claude Code via the
  marketplace, and indirectly by Codex/OpenCode via the install scripts, which
  copy the same skill directories elsewhere.

**`Kb` is the facade.** Every query the server can answer — search, outline,
get, checklist, related, info, and the catalogue's entry and graph lookups — is a
method on `owasp_kb.core.kb.Kb`, taking a
`sqlite3.Connection` and returning typed dataclasses (`core/models.py`).
`server/tools.py` does nothing but call a `Kb` method, catch its exceptions,
and reshape the result into a JSON-able dict. **There is no retrieval logic in
`server/`** — no SQL, no ranking, no fusion. That split exists so the
retrieval quality tests (`tests/test_retrieval_quality.py`) exercise `Kb`
directly against a real built index, without an MCP client in the loop, and so
a change to how search ranks results can never require touching the server.

## Pack registry

A **pack** is one ingested knowledge base, recorded in the `packs` table with
a `type` of one of three values. Two of the three packs are OWASP's; `cwe` is
MITRE's — see [docs/licensing.md](licensing.md).



- **`checklist`** — an enumerable, leveled requirement set. Currently only
  `asvs`. Supports `owasp_checklist` (enumerate by chapter/section/id/level)
  in addition to the corpus-navigation tools below.
- **`corpus`** — a document collection with no per-item structure beyond
  headings. Currently only `cheatsheets`. Supports `owasp_search`,
  `owasp_outline`, `owasp_get` — not `owasp_checklist`, which raises
  `ValueError` naming the tools that do apply if called against a corpus pack.
- **`catalogue`** — keyed entries plus a relationship graph, each entry
  addressable by the id a citation carries. Currently only `cwe`. Adds rows to
  `catalogue_entries` and supports `cwe_get`, `cwe_search`, `cwe_related`
  alongside the corpus-navigation tools, which work on it but are rarely what
  you want: an entry has one or two sections, so its outline is `[Description]`.

`owasp_related` and `owasp_search` work across all three types uniformly, because
all ultimately resolve to rows in `chunks`. The CWE graph is the exception, and
`cwe_related` exists because of it: `owasp_related` disambiguates its `id`
argument by counting dots in an ASVS requirement id, so a `CWE-nnn` cannot reach
it. See
[docs/kb-packs.md](kb-packs.md) for the full contract and how to add one.

## Schema

```
packs         (id, name UNIQUE, type CHECK IN ('checklist','corpus','catalogue'),
               version, source_url, commit_sha, license, fetched_at)
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
catalogue_entries
              (id, pack_id -> packs, entry_id, kind, name, abstraction, status,
               description, extended_description, chunk_id -> chunks;
               UNIQUE(pack_id, entry_id))
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
requirement-to-CWE, requirement-to-NIST, v5-to-v4, and CWE's own graph — is one
row in `links`, keyed by `(from_kind, from_id, to_kind, to_id, rel)`. Seven `rel`
values exist; the first four are authored joins *between* packs, the last three are
one pack's internal structure:

| `rel` | From → To | Source file | Edges |
|---|---|---|---|
| `guidance` | ASVS section/chapter → cheat sheet `doc_key` | `IndexASVS.md` | 167 |
| `cwe` | requirement → `CWE-nnn` | `v5.0.be_cwe_mapping.json`, translated through `mapping_v5.0.be_to_v5.0.0.yml` | 204 |
| `supersedes` | requirement → its v4.0.3 predecessor | `mapping_v5.0.0_to_v4.0.3.yml` | 265 |
| `nist` | requirement → a NIST SP 800-63B section | `nist.md`, composed through `supersedes` | 48 |
| `cwe_child` | `CWE-nnn` → its ChildOf parent | `cwec_v4.20.xml` | 1,160 |
| `cwe_peer` | `CWE-nnn` → a related weakness, any non-`ChildOf` nature | `cwec_v4.20.xml` | 284 |
| `cwe_member` | a CWE Category → its members | `cwec_v4.20.xml` | 4,260 |

`cwe_peer`'s name promises more than it carries: the ingest maps every non-`ChildOf`
nature onto it, and the plurality of the 284 is `CanPrecede` (143) — a directed
sequence relation — not `PeerOf` (98). The nature is not preserved in `links`, and the
edge is written in one direction only, so neither symmetry nor similarity can be read
off the `rel`. See [docs/tools.md](tools.md) for the full breakdown.

The `cwe_*` three are traversed by `cwe_related`, not `owasp_related`: the latter
disambiguates its `id` argument by counting dots in an ASVS requirement id, so a
`CWE-nnn` never reaches it. A `cwe_member` or `cwe_peer` edge can point at an id
with no `catalogue_entries` row — CWE Categories group ids from outside what this
pack ingests — so the join that resolves an edge's target is a LEFT JOIN and the
target's `abstraction` comes back `null` rather than the edge vanishing.

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
  inside a fence, targeting `DEFAULT_MAX_TOKENS = 512` (a `len(text)//4`
  estimate, not a real tokenizer count — cheap and sufficient for a split
  threshold), matching the embedder's context window exactly. 1.4% of chunks
  still exceed that limit (141 of 4,869), against an 8% build gate: the worst
  offender is 97% a single fenced code block,
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

## The assessment layer

Everything above serves knowledge. The other half of the product *uses* it: an
ASVS assessment run as a fan-out of subagents rather than by one agent working
down a checklist. Two of the four skills (`owasp-asvs-verify`,
`owasp-asvs-gap-report`) drive it; the five roles it dispatches are defined in
`plugins/owasp-kb/agents/`; and the rules it cannot be trusted to follow are
enforced in `owasp_roster` (`core/roster.py`), a tool with no retrieval in it at
all.

### Why a fan-out exists

The single-agent version was measured against a real target (an ESP32 firmware
codebase, 385 source files, 253 requirements at L2, a 544-line report):

| | |
|---|---|
| MET 21 (8.3%) / FAIL 62 (24.5%) / **N/A 170 (67.2%)** | verdict distribution |
| **~8 sentences** | the total justification behind all 170 N/A verdicts |
| 29 / 19 / 18 | requirements retired by a *single* sentence, for V10 / V3 / V7 |
| checklist 33, related 50, `kb_info` 1, search 0, outline 0, get 0 | **2 of 6 tools used** |
| 0 of 62 | findings carrying a remediation citation |

Two thirds of the output was the part nobody checked, and the agent that wrote
those exemptions was the same one that accepted them. The design goal that
follows is one sentence: **no verdict is graded by the agent that produced it.**
Exemptions are challenged before findings are, because the FAILs already carry
evidence a reader can check and the N/A verdicts carry none — a silently
under-scoped report that reads as complete is the failure this project exists to
prevent.

The fan-out is **not** a token optimisation, and was not justified as one. The
sum of 17 per-chapter L2 `owasp_checklist` calls is 75,626 chars against 74,666
for one unfiltered call — fanning out costs slightly more in total. What it buys
is peak context per agent: the largest single chapter is 10,481 chars against
the whole set's 74,666, roughly a 7× reduction, and each agent's context holds
one chapter's problem instead of seventeen.

### The five roles

| Role | Model | Tools | Sees | Produces |
|---|---|---|---|---|
| `owasp-scope-inventory` | haiku | `Read, Grep, Glob` | one concern of the codebase | facts, no security judgement |
| `owasp-chapter-orchestrator` | sonnet | `ToolSearch, Task, Read, Grep, mcp__…__*` | one chapter, the level, the inventory | that chapter's verdicts |
| `owasp-requirement-finder` | haiku | `ToolSearch, Read, Grep, Glob, mcp__…__*` | one requirement's text, the relevant inventory slice | `MET`, `GAP` with file and line, or `INSUFFICIENT EVIDENCE` |
| `owasp-exemption-refuter` | sonnet | `Read, Grep, Glob` | the exemption *claim* only | `exemption_refuted` / `exemption_holds` / `unclear`, always with `searched` |
| `owasp-finding-verifier` | sonnet | `ToolSearch, Read, Grep, Glob, mcp__…__*` | the claim and its location | `confirmed` / `refuted` / `unclear`, plus source→sink trace, CWE and remediation; a `refuted` verdict carries `mitigations_present` and `mitigation_location` instead |

The `tools:` line is the enforcement mechanism, not documentation of intent —
see ADR [0009](decisions/0009-agent-definitions-over-skill-prose.md). Four
asymmetries in it are deliberate, and each is pinned by a test in
`tests/test_packaging.py`:

- **No role may write.** Not one of the five declares `Write` or `Edit`. An
  assessment reads a codebase; nothing about it needs to change one.
- **The refuter has no MCP access and is never given the requirement text.**
  Handing it either invites re-deriving the original reasoning. Its question is
  narrower than "is this chapter satisfied": *does this codebase contain the
  thing being exempted, under any name?* — a session is still a session if the
  code calls it a peer context. Blindness is the point, so it is a missing
  capability rather than an instruction.
- **The finder may never return N/A.** Whether a requirement applies is decided
  elsewhere and must be separately refutable. A requirement that looks
  irrelevant gets `INSUFFICIENT EVIDENCE` with a reason, never a quiet
  exemption. In the baseline, exemption and finding came out of the same
  reasoning in one pass — which is how 67% of verdicts went unchecked.
- **Only the orchestrator holds `Task`.** The shape of the fan-out is a
  capability, not a convention: no other role can widen it.

The scope inventory and the refuter get no MCP access because neither needs the
standard — one reports what exists, the other searches for a construct. The
other three reach the knowledge base directly for every claim they make, rather
than receiving requirement text through a prompt where it could be truncated or
paraphrased upstream.

### The dispatch shape

```
  main session (owasp-asvs-verify)
    │  scope interview; find prior assessments; triage 17 chapters
    │  APPLIES / EXEMPT centrally — one judgement over seventeen items
    │
    ├── owasp-scope-inventory  × 6 concerns          (parallel, no KB)
    │     endpoints · middleware · identity · storage · crypto · client
    │
    ├── owasp-chapter-orchestrator  × APPLIES chapter
    │     │  owasp_checklist for its own requirements
    │     ├── owasp-requirement-finder  × applicable requirement  (up to 47)
    │     └── owasp-exemption-refuter   × 1, batched over the chapter's
    │            requirement-level N/A claims
    │
    ├── owasp-exemption-refuter  × EXEMPT chapter    (adversary)
    ├── owasp-finding-verifier   × GAP               (adversary)
    │
    └── owasp_roster(...)  → the report
```

A full L2 run against the measured target is ≈168 agents (6 inventory + 10
orchestrators + 83 finders + 7 refuters + 62 verifiers).

**Orchestrators dispatch synchronously and wait.** Parallel batches within a
turn are fine; backgrounding is not. A real run dispatched 10 finders in the
background, returned "waiting for the remaining 6 background finder agents" as
its answer, and recovered **0 of 10 verdicts** — while sitting at 45 tool calls
against a cap of 60, so no cap would have caught it. Sequential dispatch costs
wall-clock, which this design ranks lowest; losing every verdict costs the
assessment. Flattening the tree instead was rejected because the main session's
context would then hold every finding, which is the problem the fan-out exists
to solve; having finders write verdicts to files was rejected because it
requires granting `Write`.

Two guards exist where code cannot reach into a subagent:

- **The `REPORT COMPLETE` sentinel.** Every role ends its reply with it, and a
  reply without it is discarded as cut off however complete it looks. This tests
  for *the presence of a finished answer* rather than for any particular way of
  failing to produce one, which is why it catches both truncation and an early
  return with a status line.
- **`maxTurns` as a rabbit-hole detector, not a budget.** 75 for the four leaf
  roles, 200 for the orchestrator (a large chapter is 47 finders, each of which
  must return first). Set at roughly 3× observed need, so reaching a cap means
  something went wrong rather than that the work was large. Note that a turn is
  not a tool call — one agent made 37 tool calls inside 20 turns, because
  parallel calls batch into one turn.

### The verdict model

`owasp_roster` places every requirement in exactly one of seven verdicts
(`VERDICTS` in `core/roster.py`):

| Verdict | Meaning | Adversary required |
|---|---|---|
| `MET` | control present and read | — |
| `GAP` | control absent or inadequate | **`owasp-finding-verifier`** trace |
| `GAP (unconfirmed)` | reported, verification inconclusive twice | — (lands in `needs_attention`) |
| `N/A (verified)` | exempt, and a refuter searched and returned `exemption_holds` | **`owasp-exemption-refuter`** trace |
| `N/A (unverified)` | exempt, refutation inconclusive | — (lands in `needs_attention`) |
| `INSUFFICIENT EVIDENCE` | could not be determined | — (lands in `needs_attention`) |
| `INSUFFICIENT EVIDENCE (gap refuted)` | reported gap disproved by a verifier | **`owasp-finding-verifier`** trace |

The rule generalises as `CLAIMS_NEEDING_AN_ADVERSARY`: **a verdict that asserts
someone checked something must carry that check.** `GAP (unconfirmed)`,
`N/A (unverified)` and plain `INSUFFICIENT EVIDENCE` are the honest ways past
it, and all three surface in `needs_attention` rather than reading as settled.
`require_verification=False`
is the deliberate way past it, and the response says so.

The map carries each verdict's fallback alongside its adversary, so the error
names the honest verdict to record instead — `GAP (unconfirmed)` for a `GAP`,
`N/A (unverified)` for a verified N/A, and plain `INSUFFICIENT EVIDENCE` for a
refuted gap. That last one is the point of #64: a refuted gap is neither `MET`
nor "nobody looked", and 32 of 253 requirements sat in the wrong verdict because
there was no third state.

Resolution is deterministic, in code rather than prose. One refutation outweighs
any number of confirmations — finding the exempted construct is positive
evidence, failing to find it is not — and an errored adversary escalates rather
than counting as agreement. Findings dedupe on `(file, line, cwe, verdict)`; a finding
with no location never merges with another. `unclear` is not `exemption_holds`:
a claim that survives only because nobody could disprove it is unverified, and
attaching the refuter's `searched` line to it as a trace would make it
indistinguishable from a real exemption.

One seam has already failed this way. The finder's prompt named `PASS` for what
the roster calls `MET`, with nothing translating between them, so every passing
requirement would have been rejected at assembly. Each vocabulary was internally
consistent, which is why the full suite and five review rounds missed it and the
first real end-to-end run hit it in the first minute. Both sides now say `MET`,
and a test asserts the finder cannot name a verdict the roster rejects (#25).

### Where enforcement lives

This is the load-bearing decision of the whole layer, and ADR
[0010](decisions/0010-enforce-invariants-in-code.md) records it: the invariants
are enforced **in `owasp_roster`, at the assembly point every assessment must
pass through**, not asserted in the prompts. `build_roster` raises `RosterError`
on:

- a verdict outside `VERDICTS`;
- a `GAP` or `GAP (unconfirmed)` with no file and line — a gap with no location
  reaches the report pointing at nothing;
- a finding citing a requirement outside the assessed set — scope and findings
  disagreeing is an error, not something to reconcile quietly;
- a chapter with no applicability state — every chapter is `APPLIES` or an N/A
  state;
- a claim needing an adversary that carries no trace;
- a finding citing an excluded prior assessment in its `file`, `evidence`,
  `trace` or `remediation` (ADR
  [0011](decisions/0011-prior-assessments-excluded.md)).

And a requirement nobody reported becomes `INSUFFICIENT EVIDENCE` rather than
disappearing — completeness is decided by the tool, not asserted by the agent.

The reason for putting it here rather than in the role prompts is empirical.
Six defects in this project's own history were prompts saying something that
nothing downstream required: the skill asked for cheat-sheet guidance while the
output table had no guidance column, so 62 findings shipped with 0 remediation
citations (#8); 172 findings shipped unverified (#15); three of five roles could
not load the MCP tools their prompts told them to load (#19); agents returned an
opening sentence and it read as an answer (#20); an orchestrator returned a
status line as a result (#21); and the finder emits a verdict word the roster
does not accept (#25). Of those, #15 and #19 turned out to be caused by the tool
allowlists rather than by an unconsumed instruction — the "no downstream
consumer" frame was applied to #15 and then retracted by its author — but the
conclusion is the same either way: an instruction with no consumer gets skipped,
and a required field cannot be.

The limit is worth stating plainly. This catches what reaches the report; it
does not catch what an agent read and was anchored by. An agent that opens an
excluded prior assessment and then writes a finding citing only source code is
indistinguishable from one that never opened it, and on the first real run under
these rules a finder grepped and quoted an excluded file — the orchestrator's
own diligence kept it out of the report, which is exactly the disposition-based
catching that the code checks exist to stop relying on.
