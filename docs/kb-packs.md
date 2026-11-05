# Knowledge base packs

A **pack** is one ingested knowledge base. The server has no hardcoded notion of
"ASVS", "Cheat Sheets", "CWE" or "MASVS" beyond the four rows currently in the
`packs` table — everything else is generic over the pack contract below.

**Three of the four packs are OWASP's and one is not.** `asvs`, `cheatsheets` and
`masvs` come from the OWASP Foundation; `cwe` is MITRE's Common Weakness
Enumeration, and it is a pack because ASVS maps its requirements to CWE ids, so
an agent holding a CWE id needs somewhere to check it. Nothing in the contract
below is OWASP-specific, and a reader should not infer from the repository's
name that everything it serves is OWASP's — `kb_info` reports each pack's
`license` and `source_url` for exactly that reason. See
[docs/licensing.md](licensing.md).

Adding a new pack should not require a server change, and for a pack shaped like
one that already exists it does not. CWE was the first that needed new tools
(`cwe_get`, `cwe_search`, `cwe_related`) because its structure is a relationship
graph, and no existing tool could traverse one. That is a limit of the contract,
recorded in the dated note on
[ADR 0005](decisions/0005-pack-registry.md) rather than papered over.

## The contract

Every pack is one row in `packs` (see `core/schema.py`):

```
packs (id, name UNIQUE, type CHECK IN ('checklist','corpus','catalogue'), version,
       source_url, commit_sha, license, fetched_at)
```

All fields except `commit_sha` are required for every pack:

- **`name`** — the string every tool's `pack` argument matches against
  (`"asvs"`, `"cheatsheets"`, `"cwe"`, `"masvs"`). Stable forever once shipped,
  since it appears in citations.
- **`type`** — `checklist`, `corpus` or `catalogue`, validated by
  `registry.upsert_pack` before the row is written; an unknown type raises rather
  than silently storing garbage.
- **`version`** — a human string surfaced by `kb_info` and embedded in every
  citation for a `checklist` pack's requirements (e.g. `ASVS 5.0.0 V6.2.1`).
  For a release-pinned pack this is the release version (`5.0.0`); for a
  commit-pinned pack it is whatever the lock file's `version` field holds
  (the Cheat Sheet Series uses the fetch date, `20260724`, since a raw SHA is
  not a meaningful citation string on its own). CWE is release-pinned, `4.20`.
- **`source_url`**, **`commit_sha`**, **`license`**, **`fetched_at`** —
  provenance, all surfaced by `kb_info` so an agent (or a human auditing a
  citation) can trace exactly what was ingested and under what license.

Beyond the `packs` row, every pack contributes rows to `docs`, `sections`, and
`chunks` (its retrievable content) — a `checklist` pack additionally
contributes to `requirements`, one row per enumerable item, each pointing at
exactly one `chunks` row via `chunk_id`, and a `catalogue` pack to
`catalogue_entries`, one row per keyed entry, likewise pointing at one chunk.

## The three types, and which tools apply

| Type | Structure | Tools that apply | Current pack |
|---|---|---|---|
| `checklist` | Enumerable items (requirements); levels are optional, not part of the type | `owasp_search`, `owasp_outline`, `owasp_get`, `owasp_checklist`, `owasp_related` | `asvs`, `masvs`, `aisvs` |
| `corpus` | Document collection, headings only | `owasp_search`, `owasp_outline`, `owasp_get`, `owasp_related` | `cheatsheets` |
| `catalogue` | Keyed entries and a relationship graph | `owasp_search`, `owasp_outline`, `owasp_get`, `cwe_get`, `cwe_search`, `cwe_related` | `cwe` |

`owasp_checklist` is the one tool gated by type: calling it against a `corpus`
pack raises `ValueError` naming `owasp_search`/`owasp_outline` as the
alternative (`Kb.checklist` in `core/kb.py`) rather than returning an empty or
misleading result. Every other tool is type-agnostic because it ultimately
operates on `chunks`, `docs`, or `links` rows, none of which differ in shape
between the three types.

The `catalogue` row is the one to read carefully, because it is the type that
found the contract's edge. The type-agnostic tools do work on it unchanged — its
entries are `docs`, `sections` and `chunks` like everything else, so
`owasp_get("CWE-789")` returns the description text and `cwe_search` is a thin
restriction of `owasp_search` to one pack rather than a second retrieval path.
(`owasp_outline` also works, and is nearly useless here: a catalogue entry has one
or two sections, so the outline it returns is `[Description]`. Working and worth
calling are different things.) What the contract had no answer for was the graph:
`Has_Member`, `ChildOf` and `PeerOf` are `links` rows, but `owasp_related`
disambiguates its `id` argument by counting dots in an ASVS requirement id, so a
`CWE-nnn` was never going to reach it. `cwe_related` exists for that, and
`cwe_get` because a keyed entry must resolve or error — an unknown id returning
`[]` is how a mis-cited number reaches a report.

## Adding a pack

No server change is required. The path is entirely in `ingest/`:

1. **Add a lock entry** in `sources.lock.yml` under `packs.<name>`: `type`,
   `repo`, `version`, `license`, and either `release` (never `latest` —
   `load_lock` rejects it, see [docs/build.md](build.md)) or `commit`, plus
   whatever `assets`/`paths`/`extra_paths` your ingest module needs to locate
   its source files under the fetched `data/<name>/` directory.

2. **Write an ingest module** under `ingest/packs/<name>.py`, following the
   existing shape of `asvs.py` (for a `checklist` pack) or `cheatsheets.py`
   (for a `corpus` pack):
   - Call `registry.upsert_pack` first, then `registry.pack_id` to get the id.
   - Clear any existing rows for this pack first (see `_clear_pack` in either
     module) so a rebuild is idempotent rather than duplicating content —
     delete in FK order: `requirements` (if any) → `chunks` → `sections` →
     `docs`.
   - Insert `docs`/`sections`/`chunks` for your content. Use
     `core/chunking.chunk_markdown` if your source is markdown; write your own
     splitting only if the source format genuinely isn't (ASVS's flat JSON
     needs none — each requirement becomes one chunk directly).
   - Return a count (requirements or documents ingested) for the build report.

3. **Register the module in `ingest/build.py`**: import it, call it inside
   `build_index` alongside the existing three calls, and add its count to
   `BuildReport`. If the new pack should participate in any `links` edges
   (e.g. a `guidance` mapping references it), extend the relevant
   `ingest_*_links` function in `ingest/links.py`, or add a new one and a new
   `rel` value — extending `EXPECTED_REL_TYPES` in `core/integrity.py` if the
   new edge type should be enforced as non-empty.

4. **Add fixtures** under `tests/fixtures/` — a small, hand-trimmed sample of
   the real source format — and a test module under `tests/ingest/` that
   builds a tiny index from the fixture and asserts row counts and a couple of
   specific rows, following `tests/ingest/test_asvs.py` or
   `test_cheatsheets.py`.

5. **State the integrity expectation.** If the new content should always
   produce a non-trivial number of rows, edges, or both, add a floor to
   `MIN_EDGES_PER_REL` (for edges) in `core/integrity.py`, or extend the
   requirement-count check pattern for a new `checklist` pack. `run_checks` is
   what turns "an upstream format silently changed and now nothing ingests"
   into a build failure instead of a quietly smaller index — see the CWE
   mapping incident recorded in that module's docstring and in
   [docs/build.md](build.md).

No step above touches `server/` — provided the new pack's shape is one an existing
tool can already reach. Of the ten tools, the seven `owasp_*`/`kb_info` ones
generalize over any pack that satisfies the contract, and a correctly-shaped new
pack is immediately queryable by all of them (`owasp_checklist` and `owasp_roster`
only if `type = 'checklist'`, since both enumerate a requirement set). The three
`cwe_*` tools are pack-specific by construction and are the counterexample: CWE
satisfied the contract and was still not fully queryable, because a relationship
graph has no reachable surface in a heading-and-anchor API. Expect a genuinely new
*shape* to need new tools; expect a new pack of an existing shape not to.

## The MASVS pack

`masvs` (`sources.lock.yml`, release-pinned to `v2.1.0`) ingests 8 groups holding
24 controls from the release's `OWASP_MASVS.yaml`. It is `checklist`-typed, like
`asvs`, and reached by the same tools — but its shape and ASVS's diverge in
several ways worth recording, because each is a decision, not an accident of
the source format.

**Two-tier, and the group fills both columns.** ASVS is chapter → section →
requirement; MASVS 2.x is group → control, one tier shallower. `ingest_masvs`
(`ingest/packs/masvs.py`) writes the group id and title into both
`chapter_id`/`chapter_name` and `section_id`/`section_name`, so
`owasp_checklist(pack="masvs")` returns each chapter holding exactly one
section. The alternative — inventing a synthetic middle tier — would assert
structure the standard does not have, for the sole benefit of matching ASVS's
shape; the two-tier response is honest about what MASVS actually is.

**No levels, and the refusal that follows from it.** `requirements.level` is
`NULL` for every MASVS row: v1's L1/L2/R disappeared in the 2.x rewrite, and the
levels that replaced them (MAS profiles) live on MASTG tests, not on MASVS
controls. `requirements.level` is nullable to make room for exactly this case,
and both `Kb.checklist` and `Kb.search` refuse a `level`/`level_exact` filter
against a pack whose rows carry none (`Kb._reject_level_for_levelless_pack`),
rather than running the filter and returning `[]`. `[]` reads as "nothing in
this pack meets that level," which is a different and more dangerous claim
than "this pack has no levels" — the same reasoning `Kb.search` already
applies when it raises `LookupError` instead of returning an empty list for a
query that matched nothing. An empty-string sentinel was considered and rejected on a measured
comparison, not a hunch: SQLite's `CAST('' AS INTEGER)` is `0`, and `0 <= 2` is
true, so a level='2' filter would have silently passed every row rather than
none — the *opposite* failure from `[]`, and a quieter one, since the response
looks exactly like a correctly filtered result. `NULL` is the one representation
neither comparison accepts, so it's the one that fails loud. `owasp_checklist`
carries this through to its response shape: a level-less requirement omits the
`"L"` key entirely rather than emitting `"L": null`, because a null in a tool
response is a value an agent has to interpret and there is nothing here to
interpret.

**Ordering is data, not a parsed id.** `requirements.ord` — a per-pack,
dense-from-0 ordinal, `UNIQUE (pack_id, ord)` — is the sole thing
`Kb.checklist` orders by (`ORDER BY ord`, `core/kb.py`). It replaced an
expression that parsed ASVS id syntax (`SUBSTR(chapter_id, 2)`, the dot in
`section_id`) directly in SQL, which evaluated to `0` for every row of any pack
whose ids are not shaped `V<n>.<n>.<n>` — MASVS ids are `MASVS-STORAGE-1`, so
that expression would have left the second checklist pack ordered by whatever
the table scan happened to yield. Each ingest module now assigns its own dense
ordinal as it inserts rows, so ordering is a property of the data every pack
writes, not of a query that only ever understood one pack's id grammar.

**Group-description chunks, and no requirement row.** Each group's own
description prose — the paragraph explaining what the category covers, which no
individual control's one-line statement does — is inserted as one or more
`chunks` rows with no corresponding `requirements` row, retrievable by
`owasp_search` or `owasp_get` but absent from `owasp_checklist`'s enumeration
and from any requirement count. It cites as `MASVS-STORAGE#masvs-storage` —
`doc_key#anchor`, the same shape as a Cheat Sheet Series citation — because
nothing about it is a requirement to verify; it is context for the controls
that follow. `MASVS-PRIVACY`'s overview sits close enough to the embedder's
512-token window that it measurably crosses it at `v2.1.0`, so long overviews
are split on paragraph boundaries via `chunking.split_prose` — the same
primitive `chunk_markdown` uses internally, applied directly here because this
prose has no heading structure for `chunk_markdown` to walk.

**No links.** The pack ships zero `links` rows: MASVS carries no upstream
mapping of its own, and this project does not author mappings it did not
receive from upstream data (the same principle the CWE pack's entry above
states for `ChildOf`/`PeerOf`). A `MASVS → MASTG` "how do I implement this"
edge, the mobile equivalent of ASVS's `guidance` link into the Cheat Sheet
Series, is tracked separately as issue #61 — MASTG's v1 tests carry a
`masvs_v2_id` in their front matter and can be joined directly, but its v2
atomic tests carry no MASVS id at all, only a `weakness: MASWE-nnnn`, so
reaching those requires the MASWE mapping as the bridge.

## The AISVS pack

`aisvs` (`sources.lock.yml`, tag `v1.01`) ingests 213 requirements in 12
chapters from the AI Security Verification Standard: 57 at L1, 110 at L2 and
46 at L3. It covers what ASVS and MASVS do not: LLM applications, agents, RAG
pipelines, MCP servers and the model lifecycle. Its shape is ASVS's — chapter,
section, numbered requirement, cumulative levels 1–3 — so it needs no new tool.
Issue #87 left four decisions open; this section records them.

**The pin is `1.01/en/`, not `1.0/en/`.** Tag `v1.01` carries both folders.
`1.0/LOCKED.md` names 1.01 "the latest stable release", and `1.01/LOCKED.md`
freezes `1.01/en/` as the citable `v1.01-Cx.y.z` text. 1.01 adds 22
requirements to 1.0's 191 and rewords others. The release's only asset is a
PDF, so the build fetches the 12 chapter Markdown files from the tag
(`extra_paths`) and `ingest/packs/aisvs.py` parses their requirement tables.

**Ids keep the upstream `C` prefix.** A requirement is `C10.2.2`, its section
`C10.2`, its chapter `C10`, and a search hit cites `aisvs 1.01 C10.2.2`. The
prefix is AISVS's own citation form, and it is also load-bearing: `links` ids
carry no pack, so a bare `10.2.2` would sit beside ASVS's `V10.2.2`.

**A removed requirement is not ingested.** 1.01 keeps `10.2.6` as a numbered
row reading `Requirement removed.` with no level. The ingest skips that exact
tombstone and raises on any other row without a level, a row whose number does
not match its section, or a chapter with no requirement rows.

**Prose is retrievable, references are edges.** Each chapter's Control
Objective cites as `C2#control-objective`, and section intro prose sits under
the section's anchor (`C2#c21`), both as chunks with no requirement row, like
MASVS's group descriptions. The References list is not indexed; its cheat
sheet links become `guidance` edges.

**Guidance edges come from three sources, and one is ours.** No
`IndexASVS.md` exists for AISVS, so `ingest_aisvs_guidance_links`
(`ingest/links.py`) writes chapter-level `aisvs_section` edges from, in order
of authority:

1. `AISVS chapter references` — the cheat sheet links in AISVS's own chapters
   (C2 → LLM Prompt Injection Prevention, C10 → MCP Security).
2. `cheat sheet links to AISVS` — cheat sheets that link an AISVS chapter (RAG
   Security → C8).
3. `owasp-kb curated AISVS map` — the reviewed map in
   `ingest/aisvs_guidance.py`.

The third is an exception to the principle stated under the MASVS pack, that
this project does not author mappings upstream did not provide. Without it,
`AI_Agent_Security`, `Secure_AI_Model_Ops` and `Secure_Coding_with_AI` link to
no requirement, and the discovery path stops at the cheat sheet. The map is
kept honest three ways: each entry names the cheat sheet sections that justify
it, every curated edge carries its own `source` so `owasp_related` shows it is
not OWASP's, and a curated chapter the ingested release lacks fails the build.
Upstream wins a duplicate, because its edge is inserted first. The AISVS
research wiki (`1.01/research/`) holds finer, per-section links, but it is
AI-generated and `LOCKED.md` lets it change by automation, so it is not a
source.

**Appendices B and C stay out.** Appendix C's `AC.x.y` requirements govern
using AI to write code, not building AI systems, and would distort the level
counts. Appendix B is a reverse index from controls to requirement ids; whether
it becomes searchable text or edges is a follow-up, not part of this pack.

**A level filter with no pack now means ASVS and AISVS.** `0x03-Using-AISVS.md`
aligns the levels one to one and has AISVS L*N* assume ASVS L*N*, so
`owasp_search(level="2")` returns both standards. Nothing in the code changed
for this; only the tool descriptions did.

## Deliberate omissions

Two notes before the list, because the list used to carry an unstated assumption.

**This section is about OWASP projects, and the pack registry is not.** Every
entry below is an OWASP project weighed and declined. CWE was never in this list —
it was not recorded as a deliberate omission and then reversed; it was simply
outside the frame, because until now the only question asked here was "which
*OWASP* project next". Nothing was overturned by adding it. What was wrong was the
frame, and the frame is what the paragraph above the list now states.

**Why CWE became a pack when it had not been considered as one.** The ASVS→CWE
mapping has shipped since 0.2.0, and for as long as it was the only CWE content,
the reasonable position was that this server carries OWASP's *reference* to CWE
and CWE itself lives elsewhere. What broke that position was measurement, not
appetite: of 95 CWE ids cited in findings in one real assessment, 42 were absent
from the mapping. For those 42 there was no elsewhere — nothing in the toolchain
could resolve the id, so it was recalled from training data and asserted, which is
the one failure mode this whole project exists to remove. A mapping to a catalogue
you do not hold is a citation you cannot check.

**MASVS was in this list and is no longer, because it is now built — and the
entry being removed was wrong on its own terms, not just stale.** It described
MASVS as "`checklist`-shaped, much like ASVS", and both halves undersold the
difference: MASVS is two-tier (a group fills both the chapter and the section),
not ASVS's three, and it carries no levels at all, where ASVS has three. See
[the MASVS pack](#the-masvs-pack) above for what actually shipped.

The following OWASP projects are **not** packs, on purpose — not oversights:

- **WSTG** (Web Security Testing Guide) — a testing methodology, not a
  requirement or reference corpus; a different shape of content than either
  existing pack, better served by its own design than forced into `checklist`
  or `corpus`.
- **Top Ten**, including the Top 10 for LLM Applications and the MCP Top 10 —
  summaries of categories ASVS, AISVS and the Cheat Sheets already
  cover in far more actionable detail; adding it risks an agent citing
  "A03:2021" instead of the specific requirement or cheat sheet section that
  actually explains what to do.
- **Internal/organization-specific guidance** — out of scope for this project
  entirely. `owasp-kb` packages public, openly-licensed security content — OWASP's
  and, since the CWE pack, MITRE's; an organization's own security standards are a
  different pack a deployer would add locally, following the steps above, not
  something this repository should ship.
