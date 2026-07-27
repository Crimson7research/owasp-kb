# Knowledge base packs

A **pack** is one ingested OWASP knowledge base. The server has no
hardcoded notion of "ASVS" or "Cheat Sheets" beyond the two rows currently in
the `packs` table — everything else is generic over the pack contract below.
Adding a new pack should never require a server change; if it does, that is a
bug in the contract, not a reason to special-case the new pack.

## The contract

Every pack is one row in `packs` (see `core/schema.py`):

```
packs (id, name UNIQUE, type CHECK IN ('checklist','corpus'), version,
       source_url, commit_sha, license, fetched_at)
```

All fields except `commit_sha` are required for every pack:

- **`name`** — the string every tool's `pack` argument matches against
  (`"asvs"`, `"cheatsheets"`). Stable forever once shipped, since it appears
  in citations.
- **`type`** — `checklist` or `corpus`, validated by `registry.upsert_pack`
  before the row is written; an unknown type raises rather than silently
  storing garbage.
- **`version`** — a human string surfaced by `kb_info` and embedded in every
  citation for a `checklist` pack's requirements (e.g. `ASVS 5.0.0 V6.2.1`).
  For a release-pinned pack this is the release version (`5.0.0`); for a
  commit-pinned pack it is whatever the lock file's `version` field holds
  (the Cheat Sheet Series uses the fetch date, `20260724`, since a raw SHA is
  not a meaningful citation string on its own).
- **`source_url`**, **`commit_sha`**, **`license`**, **`fetched_at`** —
  provenance, all surfaced by `kb_info` so an agent (or a human auditing a
  citation) can trace exactly what was ingested and under what license.

Beyond the `packs` row, every pack contributes rows to `docs`, `sections`, and
`chunks` (its retrievable content) — a `checklist` pack additionally
contributes to `requirements`, one row per enumerable item, each pointing at
exactly one `chunks` row via `chunk_id`.

## The two types, and which tools apply

| Type | Structure | Tools that apply | Current pack |
|---|---|---|---|
| `checklist` | Enumerable, leveled items (requirements) | `owasp_search`, `owasp_outline`, `owasp_get`, `owasp_checklist`, `owasp_related` | `asvs` |
| `corpus` | Document collection, headings only | `owasp_search`, `owasp_outline`, `owasp_get`, `owasp_related` | `cheatsheets` |

`owasp_checklist` is the one tool gated by type: calling it against a `corpus`
pack raises `ValueError` naming `owasp_search`/`owasp_outline` as the
alternative (`Kb.checklist` in `core/kb.py`) rather than returning an empty or
misleading result. Every other tool is type-agnostic because it ultimately
operates on `chunks`, `docs`, or `links` rows, none of which differ in shape
between the two types.

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
   `build_index` alongside the existing two calls, and add its count to
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

No step above touches `server/`. The seven tools already generalize over any
pack that satisfies the contract; a correctly-shaped new pack is immediately
queryable by all of them (`owasp_checklist` and `owasp_roster` only if
`type = 'checklist'`, since both enumerate a requirement set).

## Deliberate omissions

The following OWASP projects are **not** packs, on purpose — not oversights:

- **WSTG** (Web Security Testing Guide) — a testing methodology, not a
  requirement or reference corpus; a different shape of content than either
  existing pack, better served by its own design than forced into `checklist`
  or `corpus`.
- **MASVS** (Mobile Application Security Verification Standard) — genuinely
  in-scope for a future pack (it is `checklist`-shaped, much like ASVS), just
  not built yet.
- **Top Ten** — a summary of categories ASVS and the Cheat Sheets already
  cover in far more actionable detail; adding it risks an agent citing
  "A03:2021" instead of the specific requirement or cheat sheet section that
  actually explains what to do.
- **Internal/organization-specific guidance** — out of scope for this project
  entirely. `owasp-kb` packages public OWASP content; an organization's own
  security standards are a different pack a deployer would add locally,
  following the steps above, not something this repository should ship.
