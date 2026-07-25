# 3. Baked index, not runtime fetch

## Status

Accepted; runtime fetch deferred, not rejected.

## Context

The index the server serves could either be built into the Docker image at
`docker build` time (the current design), or fetched/built by the container
at startup — downloading pinned sources and running the same ingest pipeline
the first time the container runs, then caching the result.

Runtime fetch was the originally stated preference: it would let a single
published image stay current indefinitely (rebuild the index on a schedule
inside a long-running deployment, no new image needed) and would keep the
image itself small. It is **deferred, not rejected** — nothing about the
baked-index design forecloses adding a runtime-refresh mode later; it simply
was not the design built first.

## Decision

Bake the index into the image at build time (`make build` → `docker build`
with `dist/owasp-kb-*.sqlite` copied in), and ship no runtime fetch path at
all in the current server.

**Gained:**

- **`--network none` becomes possible at all.** A container that must fetch
  its index on first run needs network access at least once; a container
  that already has everything it will ever need baked in needs none, ever.
  This is the single capability the rest of the README's "Runs offline"
  argument depends on.
- **Reproducible citations pinned by image tag.** Every image also gets an
  immutable, content-pinned tag (`owasp-kb:full-asvs5.0.0-cs20260724`) baked
  from the exact `sources.lock.yml` values at build time. A citation produced
  against that tag resolves to the same text for as long as the image exists
  — a runtime-fetch design would need its own separate pinning mechanism to
  offer the same guarantee, since "the image" and "the content it serves"
  would no longer be the same immutable unit.
- **Instant start.** The server opens an already-built, already-finalized
  SQLite file and is answering queries in milliseconds. A runtime-fetch
  design pays the entire ingest pipeline's cost (fetch, chunk, embed at
  ~13 chunks/s, ~3.5 minutes for a full rebuild) on some container's first
  run, which is a bad experience for whichever invocation draws the short
  straw.

**Lost:**

- **Freshness needs a rebuild.** A baked image is exactly as current as
  whatever was pinned in `sources.lock.yml` when it was built — it cannot
  notice upstream has moved on its own. This is mitigated, not eliminated, by
  the weekly `refresh.yml` workflow, which checks upstream on a schedule and
  opens a reviewed pull request when something changed, rather than requiring
  a human to remember to check.

## Consequences

A consequence discovered only during implementation, not anticipated when
this decision was made: **WAL mode persists in the SQLite database file
header, and a WAL-mode index cannot be opened safely from the image's
non-writable directory.** The build process runs with `journal_mode = WAL`
for write performance; if that file were packaged as-is, opening it with
`mode=ro` at serve time raises `OperationalError: attempt to write a readonly
database`, because SQLite needs to create `-wal` and `-shm` sidecar files
next to it — and the image bakes the index into a root-owned `/opt/owasp-kb`
that the unprivileged server process cannot write to.

Two changes in `core/db.py` exist entirely because of this:

- The build must call **`finalize_for_readonly()`** as its last step before
  the file is packaged — `PRAGMA wal_checkpoint(TRUNCATE)` followed by
  `PRAGMA journal_mode = DELETE`, checking the WAL back into the main file and
  downgrading the journal mode so nothing needs to be written at serve time.
- Serving must open the file via **`connect(read_only=True)`**, which supplies
  not just `mode=ro` but also `immutable=1` — telling SQLite to skip locking
  and change-detection entirely, which is both required for a shared
  read-only file and only safe *because* the build already finalized it out
  of WAL mode. `connect` additionally reads the file's header directly
  (`is_wal_index`) and raises before ever attempting to open a WAL-mode file
  read-only, so a build that skipped `finalize_for_readonly()` fails loudly
  at serve time instead of silently returning wrong results.
