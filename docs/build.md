# Build

## The lock file

`sources.lock.yml` is the single source of truth for what content ships. Every
pack pins its upstream source to something immutable:

```yaml
packs:
  asvs:
    type: checklist
    repo: OWASP/ASVS
    release: v5.0.0_release
    version: 5.0.0
    ...
  cheatsheets:
    type: corpus
    repo: OWASP/CheatSheetSeries
    commit: 7d1c2d3daf632206e8f2c685214c699ff8f11938
    version: "20260724"
    ...
```

**ASVS pins a release tag; the Cheat Sheet Series pins a commit SHA — and that
difference tracks how each upstream project actually publishes.** ASVS ships
numbered releases (`v5.0.0_release`) that do not move once cut, so a release
tag is already immutable and human-meaningful — `version: 5.0.0` is exactly
what a citation should say. The Cheat Sheet Series has no release process at
all; it is a continuously-updated `main` branch with no version numbers, so
the only immutable reference available is a commit SHA. `version` for that
pack is therefore not a real upstream version — it's the fetch date
(`"20260724"`), used purely as a human-readable label in citations and image
tags; the SHA is what actually pins the content and is what
`ingest/fetch.py` checks out.

**`latest` is the ASVS bleeding-edge tag, and `load_lock` rejects it.** ASVS
publishes a `latest`/bleeding-edge tag that tracks work-in-progress content
ahead of any numbered release (the same tag the CWE mapping is keyed on — see
[Mapping coverage](#mapping-coverage) below). `ingest/lock.py`'s `load_lock`
raises `ValueError` if any pack's `release` field is literally `"latest"`,
before any fetch happens: pinning to a tag that moves underneath the lock file
would make every citation produced from that build irreproducible the moment
upstream pushes again, which defeats the entire point of a lock file.

## `make` targets

```
fetch        Download pinned upstream sources into data/
model        Download the embedding model into models/
index        Build the lite index (BM25 only)
index-full   Build the full index (hybrid) — depends on `model`
test         Run unit tests
test-quality Run the retrieval quality gate against built indexes
lint         ruff check + ruff format --check
serve        Run the MCP server against the full index, for manual stdio testing
build-lite   Build the owasp-kb:lite image — depends on `index`
build-full   Build the owasp-kb:full image — depends on `index-full`
build        build-lite + build-full
docker-smoke Verify both images serve MCP correctly with --network none
clean        Remove build artefacts (dist/, data/, models/, caches)
```

All targets that need Python run inside the devcontainer via
`docker exec -u 1000:1000 owasp-kb-dev`, configurable through the `CONTAINER`
variable.

## The two build phases

`ingest.build.build_index` runs in two phases, and the entire difference
between the `lite` and `full` variants is which phases run:

- **Phase 1 — structural ingest**, identical for both variants: fetch already
  happened; `create_schema` creates every non-vector table; `ingest_asvs` and
  `ingest_cheatsheets` populate `packs`/`docs`/`sections`/`chunks`/`requirements`;
  `ingest_guidance_links`/`ingest_cwe_links`/`ingest_supersedes_links`/
  `ingest_nist_links` populate `links`; `run_checks` validates the result.
- **Phase 2 — vector indexing**, gated entirely by one flag: `--with-vectors`.
  When set, `build_index` additionally imports `core.embed.Embedder` and calls
  `retrieval.hybrid.index_vectors`, which creates `chunks_vec` and embeds every
  row in `chunks` into it. **The exact Phase 2 change is that single
  `--with-vectors` flag** passed to `owasp_kb.ingest.build` — `make index`
  omits it (producing the lexical-only index `Kb` reports as
  `retrieval_mode = "lexical"`), `make index-full` passes it (producing
  `retrieval_mode = "hybrid"`) and additionally depends on the `model` target,
  since Phase 2 cannot run without the ONNX model already downloaded.

Both phases finish with the same finalization: `PRAGMA optimize`, then
`finalize_for_readonly` (WAL checkpoint + `journal_mode = DELETE`) — see
[docs/architecture.md](architecture.md#serving-details) for why that step is
mandatory before the file is packaged into an image.

## The three CI workflows

- **`ci.yml`** — on every PR and push to `master`: lint, unit tests, then a
  full real build (fetch → both indexes → retrieval quality gate → both
  Docker images → container smoke test). This is the workflow that actually
  exercises the real, pinned upstream content on every change, not just
  fixtures.
- **`refresh.yml`** — scheduled weekly (Mondays, 06:00 UTC) plus manual
  dispatch: runs `scripts/refresh_lock.py` to check for new upstream releases
  or commits, and if anything changed, verifies the new content still fetches
  and builds (lite index only, as a cheap sanity check) before opening a pull
  request with the updated `sources.lock.yml` for human review. Nothing is
  ever pushed to source control unreviewed.
- **`release.yml`** — on pushing a `v*` tag: reads the pinned versions out of
  `sources.lock.yml`, builds both indexes, runs the full retrieval quality
  gate, builds both images under both tag forms (see below), smoke-tests each,
  and only pushes to GHCR if every smoke test passes — a broken image is never
  published, regardless of what tag triggered the release.

## Image tag scheme

Every build produces two tags per variant:

- **A moving tag** — `owasp-kb:lite`, `owasp-kb:full` — always the most recent
  build for that variant.
- **An immutable, content-pinned tag** — `owasp-kb:lite-asvs5.0.0-cs20260724`,
  `owasp-kb:full-asvs5.0.0-cs20260724` — encoding the exact ASVS version and
  Cheat Sheet Series fetch date baked into that specific image, read directly
  from `sources.lock.yml` at build time (`ASVS_VERSION`/`CS_DATE` in the
  `Makefile`; the same values via `steps.versions` in `release.yml`). A
  citation produced against a pinned tag remains reproducible indefinitely,
  independent of whatever the moving tag points to later — see the README's
  "Reproducible citations" section.

## Mapping coverage

| `rel` | Source | Coverage | Caveat |
|---|---|---|---|
| `guidance` | `IndexASVS.md` | 167 edges, 77/80 sections | Maps sections; requirements inherit via their section |
| `cwe` | `v5.0.be_cwe_mapping.json` | 204 edges, 8 dropped | Keyed on **bleeding-edge** ids which are renumbered — 0 of 345 unchanged — so translation goes through `mapping_v5.0.be_to_v5.0.0.yml`. A prefix strip would put CWE-306 on an encoding requirement instead of V6.1.3 |
| `supersedes` | `mapping_v5.0.0_to_v4.0.3.yml` | 265 edges, 190/345 requirements | The other 155 are `ADDED` and correctly have no predecessor |
| `nist` | `nist.md` | 48 edges, 41/345 requirements | Dated 07-Nov-2024, keyed on v4.0.3 ids, so composed through `supersedes` |

A missing `cwe` or `nist` edge is **not** evidence that a requirement has no
CWE or NIST equivalent. Both mappings are structurally partial by
construction — the CWE mapping only exists keyed on ids that must be
translated (and 8 entries do not translate to any requirement in this
release), and the NIST mapping is dated over a year before this ASVS release
and keyed on the *previous* major version's requirement ids, reachable only
through whichever `supersedes` edges happen to connect a v5 requirement back
to a v4 one. `core/integrity.py` enforces a floor on every `rel` type (100 for
`guidance` and `cwe`, 150 for `supersedes`, 20 for `nist`) specifically so a
silent collapse to near-zero — the exact failure mode the CWE mapping hit
before the bleeding-edge translation step existed — fails the build instead of
shipping as a quietly smaller index.
