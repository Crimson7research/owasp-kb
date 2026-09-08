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
  happened; `create_schema` creates every non-vector table; `ingest_asvs`,
  `ingest_masvs` and `ingest_cheatsheets` populate
  `packs`/`docs`/`sections`/`chunks`/`requirements`;
  `ingest_guidance_links`/`ingest_cwe_links`/`ingest_supersedes_links`/
  `ingest_nist_links` populate `links`; `run_checks` validates the result — see
  [Per-pack requirement counts](#per-pack-requirement-counts) below.
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

## The four CI workflows

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
- **`release.yml`** — on pushing a `v*` tag: derives the version from the tag and
  writes it into `src/owasp_kb/__init__.py` before anything is built, so the image
  reports the release it was cut from rather than whatever the last hand bump left
  behind (ADR 0016). It then reads the pinned versions out of
  `sources.lock.yml`, builds both indexes, runs the full retrieval quality
  gate, builds both images under both tag forms (see below), smoke-tests each,
  and only pushes to GHCR if every smoke test passes — a broken image is never
  published, regardless of what tag triggered the release. It then captures the
  `full` image's registry digest, runs `scripts/pin_image.py --write`, and opens a
  pull request carrying the new `plugins/owasp-kb/.mcp.json`,
  `plugins/owasp-kb/pinned-packs.json` and the `src/owasp_kb/__init__.py` the tag
  wrote. **Merging that PR is the delivery step**,
  because the marketplace is read from the default branch, so master is the surface
  devs install from. The digest is only knowable after the push, which is why the
  reference the plugin ships is written by the workflow rather than by hand. The
  record beside it names the pack versions that image was built from, and the version
  the image reports — see ADR 0015 and "What the shipped pin is checked against" below.
  It also drafts the GitHub Release for the tag, left unpublished so that a release
  whose pin request never merged does not read as delivered.
- **`release-promote.yml`** — on a pull request closing: if it merged and its branch is
  `release/pin-v*`, publishes the Release that `release.yml` drafted. Delivery is that
  merge, so the Releases page and what is installable agree, and a release that stalls
  with an unmerged pin reads as incomplete rather than done.

## Image tag scheme

Every build produces two tags per variant:

- **A moving tag** — `owasp-kb:lite`, `owasp-kb:full` — always the most recent
  build for that variant.
- **An immutable, content-pinned tag** —
  `owasp-kb:lite-asvs5.0.0-cs20260724-cwe4.20`,
  `owasp-kb:full-asvs5.0.0-cs20260724-cwe4.20` — encoding the exact ASVS version,
  Cheat Sheet Series fetch date and CWE release baked into that specific image,
  read directly from `sources.lock.yml` at build time
  (`ASVS_VERSION`/`CS_DATE`/`CWE_VERSION`, composed into `PINNED_TAG` in the
  `Makefile`; the same values via `steps.versions` in `release.yml`). A
  citation produced against a pinned tag remains reproducible indefinitely,
  independent of whatever the moving tag points to later — see the README's
  "Reproducible citations" section.

  **The `-cwe<version>` component was added with the CWE pack, and the tag was
  wrong without it.** The scheme named two packs because there were two. Once a
  third pack shipped, a CWE release bump alone — 4.20 to 4.21 deprecates ids and
  renumbers others — would have produced a byte-different index under a tag
  identical to the previous one. That is precisely the drift the immutable tag
  exists to make impossible, and it became citable rather than incidental the
  moment `cwe_get` let an agent quote a CWE name and status. **Every pack in the
  index must appear in the tag**; a fourth pack means a fourth component.
  ADRs 0003 and 0004 quote the older two-pack form because that is what existed
  when they were written.

**Neither tag is what the plugin ships.** Both exist for humans and for citation
reproducibility. What `plugins/owasp-kb/.mcp.json` names is the `full` image's
**digest**, because a tag can be reassigned and, worse, is shadowed by any local
image of the same name — `--pull=missing` is docker's default and `docker tag` is
unprivileged. A digest cannot be shadowed: a local cache hit on it *is* the
published bytes.

### What the shipped pin is checked against

`scripts/verify_pin.sh` checks in CI that the shipped digest resolves and that the
image it names carries the packs recorded for it in
`plugins/owasp-kb/pinned-packs.json`, written by `scripts/pin_image.py` at release
time from the lock that build read.

It read `sources.lock.yml` directly until ADR 0015, which asserts something no
lock-bump commit can satisfy: the image holding new content is not built until the
release that follows the merge. The first refresh pull request failed on it, and
merging would have taken master with it. Drift between the record and the lock is
therefore reported and not failed —

```
note: sources.lock.yml is ahead of the shipped image -- a release is pending
  cheatsheets: shipped 20260724, lock 20260805
```

— and a release closes it. What still fails: a digest that does not resolve, an image
that does not hold its recorded packs, and a record naming some other digest (that
last one in `pytest`, since it needs neither docker nor the registry).

The base image is pinned by digest for the same reason one layer down.
`python:3.13-slim` moves, so two builds of identical source produced different
images — a hole in the reproducibility the immutable tag above promises.
`.github/dependabot.yml` bumps it, since a digest pin stops security updates
arriving on their own.

## The commit is the plugin version

Neither `plugin.json` nor `marketplace.json` declares a `version`. Claude Code
resolves an absent version to the commit the plugin was fetched at, so every commit
on the default branch is a distinct version and the plugin cache tracks commits
rather than a hand-maintained number. Observed directly: a marker commit moved an
installed copy from cache key `37b3cef5e478` to `5fbc08c9a745` and delivered the
change.

That is why `scripts/plugin_digest.py` and `content.sha256` are gone rather than
merely moved. They existed to catch a plugin content change shipped without a
version bump, which left the installed copy unreachable rather than stale:
`/plugin` reported "already at the latest version", `/mcp` reported a successful
reconnect, and `/reload-plugins` reloaded the old files — three green statuses,
every one of them true about the wrong artefact, recoverable only by uninstalling
and reinstalling, with nothing indicating that was necessary.

It cost exactly that once: a hook fix was verified in the repository, in its tests
and in CI, and was not the code running, because the cached copy of the previous
version still held the defective comparison. The verification was sound and
measured the wrong copy. It cannot happen when the version *is* the content's
commit.

`test_no_plugin_version_field_is_declared` is what keeps it that way. Re-adding
the field reinstates the hazard silently, so the test names the tooling that would
have to come back with it. It was watched failing against the field before the
field was removed.

The version in `src/owasp_kb/__init__.py` is unrelated: it versions the Python package
and the image built from it, and is reported by `kb_info` as `server_version`.
`pyproject.toml` derives from it. It is written by `release.yml` from the tag, before any
image is built, and reaches this branch through the release pull request — see ADR
[0016](decisions/0016-the-tag-writes-the-version.md) for why the order matters and what
the hand bump cost at v0.17.1. The two numbers drift on purpose — an image is released
when its content changes, and the plugin ships on every commit.

## Per-pack requirement counts

`core/integrity.run_checks` takes `expected_requirements` as a
`Mapping[str, int]` — a count per checklist pack, keyed by pack `name` — not a
single integer compared against one global `COUNT(*) FROM requirements`, which
is what it took before MASVS shipped. With more than one checklist pack a
total is meaningless: ASVS and MASVS summed would pass whether both packs are
complete or one is short by exactly what the other is long, and a single
number cannot say which pack a shortfall came from. Counting per pack instead
makes each pack's ingest accountable for its own rows.

`build.EXPECTED_REQUIREMENTS = {"asvs": 345, "masvs": 24}` is what `build_index`
and the CLI default to. Of those two figures, only 24 is pinned by a test —
`test_the_real_release_matches_the_shape_the_build_expects` in
`tests/ingest/test_masvs.py`, marked `realdata` and run against the actual
pinned v2.1.0 release asset. 345 is not asserted anywhere in the unit suite; it
is checked only when a real build runs `run_checks` against the real ASVS
ingest, so a drift in that count fails a full build, not `make test`.

`run_checks` also fails when a `checklist` pack is present in the database
(has a row in `packs` with `type = 'checklist'`) but absent from
`expected_requirements` — this is new, and deliberate: an ingest that inserts
zero rows for a newly wired pack, with nobody having added a line to
`EXPECTED_REQUIREMENTS`, would otherwise ship with nothing counting it, which
is the exact defect class [Mapping coverage](#mapping-coverage) below exists to
catch for `links` edges. Every checklist pack the build ingests must be
declared in `EXPECTED_REQUIREMENTS` in the same change that wires its ingest
call — see [Adding a pack](kb-packs.md#adding-a-pack) in `docs/kb-packs.md`.

`--expected-requirements` on `python -m owasp_kb.ingest.build` changed to
match: it is now a repeatable `PACK=COUNT` flag, one per pack, rather than a
bare integer —

```
python -m owasp_kb.ingest.build --sources data --out dist/owasp-kb.sqlite \
    --expected-requirements asvs=345 --expected-requirements masvs=24
```

— rather than the old `--expected-requirements 345`. Neither `make index` nor
`make index-full` passes the flag at all, so both build against the
`EXPECTED_REQUIREMENTS` default shown above; a malformed pair (no `=`, or a
non-integer count) is rejected before any build is attempted, logged
actionably, and exits 1 rather than surfacing as a traceback partway through.

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
to a v4 one. `core/integrity.py` enforces a floor on every one of the seven `rel`
types (100 for `guidance` and `cwe`, 150 for `supersedes`, 20 for `nist`, and for
CWE's own graph 800 `cwe_child`, 200 `cwe_peer`, 3000 `cwe_member`) specifically
so a
silent collapse to near-zero — the exact failure mode the CWE mapping hit
before the bleeding-edge translation step existed — fails the build instead of
shipping as a quietly smaller index.
