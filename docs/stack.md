# Why this stack, and when it would be wrong

This document is not a recommendation. It is an argument that the stack here —
SQLite with FTS5 and `sqlite-vec`, an index baked into a Docker image, served
by a single process under `docker run -i --rm --network none` — is a
*consequence* of ten specific properties of the content it serves.

That matters because the interesting question a reader brings to this repo is
usually not "what did they pick" but "would this work for my knowledge base?"
For a great many knowledge bases the answer is no, and the reason is not that
SQLite is small or that Docker is inconvenient. It is that the ten properties
below do not hold, and each one that fails takes a piece of the stack with it.

The decision records live in [`docs/decisions/`](decisions/) — in particular
[ADR 0002 (SQLite over Postgres + pgvector)](decisions/0002-sqlite-over-postgres-pgvector.md)
and
[ADR 0003 (baked index, not runtime fetch)](decisions/0003-baked-index-not-runtime-fetch.md).
This document does not restate them. It makes the comparison they do not: the
one against a knowledge base that is *not* shaped like this one.

---

## 1. What the corpus actually is

Ten properties. Every one of them is a fact about the content, not a preference
of this project's.

**Four of the five packs are OWASP's; one is not.** ASVS, MASVS, AISVS and the
Cheat Sheet Series are OWASP Foundation projects. The CWE catalogue is MITRE's — CWE
is **not an OWASP project**, and it sits in this server because ASVS maps its
requirements to CWE ids, not because it shares an upstream. That mapping is why
an agent ends up holding a CWE id it cannot check: it reaches only 204 of 345
requirements, and in one real assessment 42 of 95 cited ids came from nowhere in
this index at all. See [docs/licensing.md](licensing.md) for CWE's own terms.

Its properties differ from the other three OWASP packs in ways that happen to
make the argument below stronger rather than weaker. CWE publishes **numbered
releases** (`4.20`) rather than a moving branch, so property 2 holds more cleanly for it
than for the Cheat Sheet Series, which needs a commit SHA. It is **keyed**: 1,391
entries — 969 Weaknesses and 422 Categories — each addressable by the id a
finding actually cites, which is why `cwe_get` can treat an unknown id as an error
rather than an empty result. And its structure is a **relationship graph**
(`ChildOf`, `PeerOf`, `Has_Member`: 1,160 / 284 / 4,260 edges) rather than heading
hierarchy, which is the first content in this index whose shape is navigated by
edge rather than by anchor — and the reason `packs.type` needed a third value,
`catalogue`, alongside `checklist` and `corpus`.

**1. Read-only after build — exactly one writer, at build time.**
`ingest/build.py` writes the index once and nothing ever writes to it again.
Serving opens it with `mode=ro&immutable=1`, which tells SQLite to skip locking
and change detection entirely. The build must call `finalize_for_readonly()`
(`PRAGMA wal_checkpoint(TRUNCATE)`, then `PRAGMA journal_mode = DELETE`) before
the file is packaged, or serving fails loudly.

**2. Pinned to an exact upstream release.**
`sources.lock.yml` pins ASVS, MASVS and AISVS each to a release tag and rejects
`latest` — the rolling bleeding-edge build — pins the Cheat Sheet Series to a
40-character commit SHA, and pins CWE to a numbered release (`4.20`). Every
document carries a `source_url` that pins the commit, so a citation resolves
to the exact indexed text rather than to a moving branch. Every upstream
publishes numbered releases with machine-readable assets; no scraping, no
PDF parsing.

**3. Small — small enough that the database engine is not the interesting
problem.**
120 files and 2.48 MB of cheat sheets, plus 82 KB of ASVS requirement text, plus
an 18.2 MB CWE catalogue XML that reduces to 1,391 keyed entries. 1,528 documents in
the index — 17 ASVS chapters, 120 cheat sheets, 1,391 CWE entries. 4,869 chunks at
the shipped chunk size of 512 tokens (345 ASVS + 2,549 cheat sheet + 1,975 CWE).
384-dimension vectors, roughly 7.5 MB of vector data at `float32`. The index file
is 8.0 MB (`lite`) or 16.0 MB (`full`), measured on the shipped files. The whole
ASVS standard would fit in a context window, which is why the MCP server earns its
place through filtering, citation stability and cross-linking rather than through
compression.

These figures predate MASVS and are not re-measured here: `data/` is absent from
this checkout and the build job is not locally runnable, so the post-MASVS totals
are unmeasured rather than estimated. What is known from the ingest code without
building is the shape of the addition, not its size in bytes or vectors: 24
requirement chunks, one per control, plus one or more chunks per group's own
overview prose (8 groups, more than one only where `split_prose` divides an
oversized overview — measured in `ingest/packs/masvs.py` to happen for
`MASVS-PRIVACY` at `v2.1.0`).

The CWE pack roughly doubled every one of those figures and changed none of the
conclusions below. It moved the corpus from ~345× below the threshold where an ANN
index starts to matter to ~205× below it — a change of degree inside an argument
that has two orders of magnitude of headroom. MASVS's 24 requirements plus a
handful of overview chunks add far less: nothing here indicates a similar move
between the two thresholds.

**4. It does not change at runtime; freshness is a build concern.**
There is no runtime fetch path in the server at all. A baked image is exactly
as current as whatever `sources.lock.yml` pinned when it was built, and cannot
notice upstream has moved. That is tolerable because upstream moves on a
release cadence. The weekly `refresh.yml` workflow opens a reviewed pull
request rather than auto-merging, because content changes to a security
knowledge base are reviewed, not auto-merged.

**5. Citations must be reproducible, indefinitely, by a third party.**
A citation produced against the content-pinned tag
(`owasp-kb:full-asvs5.0.0-cs20260724-cwe4.20`) resolves to the same requirement text
for as long as the image exists. This property drives three otherwise unrelated
pieces of machinery at once: the immutable image tag, the anchor-uniqueness
discipline (16 slug collisions across 9 of the 120 cheat sheets in the real
corpus, the worst being 12 sections all slugifying to `do`), and the rejection
of an uncitable `SearchHit` at construction. The worst measured collision would
have served X-Frame-Options' limitations under CSP's citation — wrong security
guidance behind a plausible reference.

**6. It must run offline, with no egress, inside someone else's
security-sensitive network.**
Every documented invocation passes `--network none`. The reason is commercial
as much as technical: on a client engagement the tool has no egress path for
the codebase being reviewed, works inside deliberately locked-down networks,
and needs no allowlisting exception to pass the client's own security review.

**7. The content has real, pre-built structure worth encoding once.**
ASVS has a chapter/section/requirement hierarchy and cumulative levels. The
Cheat Sheet Series has heading structure. And OWASP itself publishes the join
between them: `IndexASVS.md` maps ASVS chapters and sections to the relevant
cheat sheets. That join is the single most valuable relationship in the
system — the requirement-to-guidance query is measured as the highest-value
query the server can answer, and it reaches 332 of 345 requirements (96.2%).

**8. Completeness matters more than response size.**
A gap report needs *every* requirement; silently dropping rows from a
compliance enumeration is worse than a large response. `owasp_checklist` does
not truncate and does not paginate. Pagination that an agent forgets to exhaust
is precisely the failure mode the design refuses. This is only defensible
because the enumerable set is bounded: 345 rows, 140,698 characters unfiltered
before grouping, 103,134 after.

**9. Three structurally different content shapes, all stable.**
`checklist` (enumerable requirement sets; levels are a property some carry, not
part of the type — ASVS does, MASVS does not), `corpus` (documents navigated by
heading) and `catalogue` (keyed entries navigated by a relationship graph). No
schema or server code names "ASVS", "cheat sheets", "CWE" or "MASVS" — they are
four rows in a `packs` table, distinguished from any future pack only by the
`type` that row carries. The third type is a partial vindication of the generic
registry and worth reading as such: no tool that predates CWE needed changing,
and no existing `Kb`
method did either. But the pack did need three *new* tools (`cwe_get`,
`cwe_search`, `cwe_related`) and two new `Kb` methods, because a graph is not
queryable through a heading API. ADR 0005's "adding a pack needs no server change"
holds for a pack shaped like the two it was written about, and does not hold in
general — see the dated note on that ADR.

**10. The consumer is an AI agent, not a human.**
This changes what absence means. An empty search raises rather than returning
`[]`, which an agent would read as "no requirements apply." An empty
`owasp_related` names the coverage gap and states that absence is not evidence.
`get_pack` raises a `KeyError` that names the available packs, because that
message reaches an agent through the MCP tool layer and has to say what to do
next. A human looking at an empty search page can see that it is empty. An
agent cannot.

An eleventh property does not shape the storage decision but is worth naming:
upstream's mappings are partial *by construction*. CWE reaches 204 of 345
requirements (59.1%), NIST 41 of 345 (11.9%), `supersedes` 190 of 345 (55.1%) —
the other 155 being genuinely new in 5.0.0. The project surfaces that coverage
rather than filling the gaps, because inventing edges would make this a source
of security claims rather than a conduit for OWASP's.

The CWE pack is what that partiality eventually cost, and it is worth separating
the two things. The pack does **not** fill in the missing 141 mappings — no edge
was invented. It makes the ids on the *other* side checkable: an agent that
departs from the mapping, which it must for 141 requirements and does anyway for
the rest, previously produced a CWE id nothing in this index could resolve. Now
`cwe_get` resolves it or errors. That is still a conduit, not a source: the
catalogue is MITRE's text, cited by MITRE's id.

---

## 2. The stack, and which property forces each part

The ordering here matters more than the list. Several of these look like they
were decided by the obvious argument and were not.

| Choice | Forced by | Not by |
|---|---|---|
| SQLite, single file | **6** (offline, one process) | scale — see below |
| `mode=ro&immutable=1` | **1** (one writer, at build) | performance |
| Baked index in the image | **6**, **5** (offline, pinned citations) | image size |
| Brute-force cosine, no ANN | **3** (4,869 vectors) | — |
| `links` edge table | **7** (upstream publishes the join) | — |
| Generic `packs` table | **9** (three shapes, more coming) | — |
| No pagination anywhere | **8** (bounded enumerable set) | — |
| Raising instead of empty results | **10** (an agent consumes this) | — |
| `sources.lock.yml`, rejecting `latest` | **2** (upstream has release tags) | — |
| Weekly reviewed-PR refresh | **4** (release cadence, not continuous) | — |

The one to read carefully is the first row. ADR 0002 is explicit that the scale
argument — 2,400 chunks, 4 MB of vectors, brute-force cosine in under 10 ms —
"alone would justify this," but that it is *not* what decided it:

> the **decisive factor** is operational: **Postgres breaks
> `docker run -i --rm --network none` as a single self-contained process.**

That ordering is the transferable part. If you take away only the scale
argument, you conclude "SQLite until we outgrow it." If you take away the
operational argument, you conclude something stronger and much less
general: this system is *defined* by being one process with no network, so any
storage engine that needs a second process is disqualified at any scale. A
knowledge base without that constraint does not inherit the conclusion.

The same inversion applies to ADR 0003. Baking the index looks like a
performance decision (instant start, versus the ~3.5 minutes and ~13 chunks/s
a runtime build would cost on some unlucky container's first run). It is not.
It is what makes `--network none` possible at all: a container that must fetch
its index on first run needs network access at least once. Performance is the
consolation prize.

A third example: `mode=ro&immutable=1` was not chosen for speed either. It
became mandatory because WAL mode persists in the SQLite file header, and a
WAL-mode index cannot be opened from the image's root-owned, non-writable
`/opt/owasp-kb` — SQLite wants to create `-wal` and `-shm` sidecars next to it.
That consequence was discovered during implementation, not anticipated.

---

## 3. Postgres + pgvector, honestly

Postgres + pgvector was the **original preference**, not a strawman. ADR 0002's
status line records the reversal in as many words: *"Accepted, superseding an
initial preference for Postgres + pgvector."* It deserves both sides.

### What Postgres would have bought

- **Concurrent writers.** SQLite's single-writer model is a real constraint,
  and it is the first thing to break if the content ever becomes mutable.
- **Hosted, multi-tenant serving.** Many tenants from one running process is
  something SQLite-per-image simply does not do.
- **ANN at scale.** HNSW and IVFFlat are real answers to a real problem — one
  this corpus does not have.
- **A richer query surface.** Recursive CTEs over the `links` graph, partial
  indexes, materialised views, `tsvector` configuration, proper `EXPLAIN`.
- **No `sqlite-vec` extension-loading dance.** Loading a compiled extension
  into SQLite from Python is fiddlier than `CREATE EXTENSION vector`.

### What it would have cost here

- **It breaks the single-process offline constraint.** Postgres needs at
  minimum a second process — in-container or sidecar — and practically it needs
  administration: backups, connection pooling, upgrade paths. None of that is
  something a `--network none` stdio MCP server has any way to need.
- **The ANN index would never activate.** pgvector's approximate-index
  machinery starts paying for itself around **10⁶ vectors**, roughly **400×**
  this corpus. Below that, brute force is not merely adequate, it is simpler
  and about as fast.
- **It is an operational dependency in a tool that must pass a client's
  security review.** "One container, no network" is a sentence a client's
  security team can evaluate in a minute. "One container plus a database" is
  a conversation.
- **Embedding cost is identical either way.** Inference lives in
  `core/embed.py`, upstream of whichever database stores the result. Nothing
  about Postgres makes it cheaper.

### The measurement that decided it

Two, really, and the first is the more interesting.

The original case for pgvector rested on a claim about paraphrase: that a query
like "stop people brute-forcing logins" shares almost no vocabulary with the
corpus and that BM25 misses it entirely, so only a real embedding model closes
the gap. On that reasoning SQLite would have been the fallback `lite` variant
and Postgres + pgvector the real architecture.

Measured, the claim was wrong. The literal string "brute force" occurs **34
times** across the 120 cheat sheets, and BM25 alone returns the expected
document inside the top 8 for **two of the four** paraphrased test queries —
including the hardest-sounding one, which it ranks **3rd**. Mean rank across
those four queries was **3.0 under BM25 alone and 2.2 under hybrid** when that was
measured; the shipped index now measures **3.2 and 2.2**, because the CWE pack put
1,391 more documents in the BM25 index and cost one rank position on one of the
four queries. The direction of the argument is unchanged and the size of the gap
grew slightly. As ADR 0002 puts it: *"The real deficiency is ranking, not presence"* — an improvement
of degree, not of finds-it-at-all. The vector half buys better ordering among
results that were mostly already there.

That reframing is what let the scale argument bite. Once vector search is a
ranking improvement rather than the only way to find anything, the question
becomes how much machinery a ranking improvement is worth over 7.5 MB of vectors.
Brute-force cosine distance over that many vectors runs in **under 10 ms**,
measured. There is nothing for an ANN index to do.

(One honest wrinkle: ADR 0002 says "~2,400 chunks", which was the pre-merge
snapshot the retrieval benchmarks ran against. The shipped index at 512-token
chunks held **2,894** before the CWE pack and **4,869** with it, before MASVS;
MASVS's contribution is unmeasured here (see property 3). Whatever it is, all
these figures stay orders of magnitude below the 10⁶ threshold, so the
conclusion is unaffected — but the ADR's figure is a snapshot, not the shipped
count, and it is now three packs behind rather than two: the original merge,
then CWE, then MASVS.)

The reversal is what makes ADR 0002 credible. A record that only stated the
conclusion — "we chose SQLite, it is small and fast" — would be indisputable
and therefore worthless. A record showing that the team's stated preference was
overturned by measuring the specific claim it rested on tells you the
conclusion was tested.

### What the ADR already concedes

> **Postgres remains the right answer for that future hosted deployment**, if
> one is ever built — this decision rejects it for the current single-process,
> offline, per-session model, not as a database in general.

And the design anticipates that migration structurally: `Kb` (`core/kb.py`) is
a thin facade whose entire purpose is containment. Every query the server can
answer is a `Kb` method returning typed dataclasses, with no SQL or retrieval
logic anywhere under `server/`. A Postgres-backed `Kb` behind the same
interface would not require touching `server/tools.py`, `server/prompts.py`, or
any skill. That facade is the cost this project pays *because* it believes
Postgres may eventually be right.

---

## 4. When this stack is wrong

Take a mutable knowledge base — a wiki, a forum, an issue tracker, a chat
archive — and walk the ten properties. Most of them fail, and each failure
removes a load-bearing piece.

**1. Read-only after build → false.** A wiki has writers, plural,
continuously. `immutable=1` becomes unsafe the moment there is a second writer,
because it tells SQLite to skip change detection: readers will happily serve
stale pages from a file that has moved underneath them. WAL becomes necessary
rather than something to strip out at build time, and `finalize_for_readonly()`
has no meaning. ADR 0002 says this out loud — the single-file, single-writer
model *"is not the right choice for a future hosted service handling concurrent
writers or serving many tenants from one running process."*

**2. Pinned to a release → false.** There is no release tag. A wiki has
revisions, a forum has post ids that can be edited or deleted, a chat archive
has no versioning concept at all. `sources.lock.yml` has no analogue: there is
nothing immutable to pin *to*. The closest substitute is a snapshot timestamp,
which is a much weaker promise — it identifies when you looked, not what you
looked at.

**3. Small → probably false, and it is the least important failure.** A
mature wiki or a decade of forum history is easily two orders of magnitude
larger, at which point ANN starts to matter and the brute-force loop does not
finish in 10 ms. But note this is the property whose failure costs the *least*:
it changes the index, not the architecture.

**4. Freshness is a build concern → false, and this is fatal to the baked
image.** A rebuild-and-redeploy loop cannot track content that changes hourly.
The `refresh.yml` model — check weekly, open a reviewed PR, rebuild, retag,
redeploy — is coherent for a standard that ships releases, and absurd for a
forum. You are now looking at incremental indexing against a live store,
which means a live store, which means not a file baked into an image.

**5. Reproducible citations → false, and this is the deepest failure.** A
citation into mutable content cannot promise to resolve to the same text next
week. The page can be edited; the section can be renamed, which moves the
anchor; the post can be deleted. Every piece of this project's citation
machinery — the content-pinned image tag, the anchor-uniqueness gate, the
`SearchHit` that refuses to exist without a resolvable target — exists to make
a promise that mutable content cannot make. You can approximate it with
revision ids, if your source has them and never hard-deletes. Most do not.

**6. Offline by construction → usually false.** If the knowledge base must
reflect live remote state, `--network none` is not a constraint you can meet;
it is a contradiction. Everything ADR 0003 gains, you forfeit.

**7. Pre-built cross-references → almost always false.** This is the
underrated one. `IndexASVS.md` is an *authored* join between two corpora,
maintained by the people who wrote both. Forum posts have nothing like it, and
neither do most wikis: wiki-links are a link graph, not a typed relationship
graph, and "page A links to page B" does not mean "B explains how to satisfy
A." Without an authored join the `links` table must be inferred — which is
exactly what this project refused when it declined to derive CWE edges from
cheat-sheet prose, on the grounds that *a mention is not a mapping*. Inferred
relationships carry a confidence the query surface has to expose, and the clean
edge-table design changes shape.

**8. Bounded enumerable set → false.** There is no meaningful "return all of
it" query over a forum, so refusing to paginate stops being defensible and
becomes negligent. Once you paginate, you inherit the failure this project
designed against — an agent that forgets to exhaust the pages and silently
reports on a prefix — and you have to solve it some other way (cursors the
agent cannot drop, or a server that refuses partial answers to
completeness-shaped questions).

**9. Two stable content shapes → likely false.** User-generated content is
heterogeneous and its shape drifts. A `type` column with two values is not the
abstraction you want.

**10. The consumer is an agent → possibly still true, and this is the one
property most likely to survive.** See the next section.

### What to reach for instead

For a mutable knowledge base with concurrent writers and live freshness:
**Postgres, with pgvector if you need semantic ranking.** Not as a default, but
because it is the thing that solves properties 1, 3 and 4 at once — one durable
store, real concurrency, incremental upsert on write rather than a rebuild, and
an ANN index that starts earning its keep past roughly 10⁶ vectors. Accept the
operational dependency: your content already forced you to have a server.

For citations, replace image-tag pinning with revision-id pinning at the
source, and say in the tool output when a cited revision is no longer current.
That is a weaker guarantee than this project offers, and you should say so
rather than let it look equivalent.

For freshness, index incrementally off the source's change feed — webhook,
outbox table, or polled cursor. The build/serve split this repo's architecture
is organised around collapses.

And keep the MCP server. Property 10 has nothing to do with storage.

---

## 5. What transfers regardless of stack

Strip out SQLite, the baked image, and `--network none`, and a set of lessons
remains. They are about serving an AI rather than about storage, and they are
the genuinely portable part of this repo.

**Never let absence read as a finding.** This is the project's recurring
principle and it appears in at least four places independently: empty search
raises a `LookupError` rather than returning `[]`; an empty `owasp_related`
names which relationship is sparse and states that absence is not evidence;
`kb_info` reports per-relationship coverage so an agent can see that NIST
reaches 11.9% of requirements before it concludes anything from a NIST silence;
and `get_pack` raises with the available pack names in the message. A human
reading an empty results page knows it is empty. An agent reads `[]` as a
finding and writes it into a report.

A fifth instance settled a design question rather than a rendering one. An
assessment's findings accumulate in a file that the roster reads; loading it
fails closed, because a missing file read as an empty set produces a roster
reporting every requirement as `INSUFFICIENT EVIDENCE` — a plausible-looking
assessment result rather than a missing file. The general rule that fell out of
it is worth carrying: **fail open when the degraded state is recognisable as
degraded, and fail closed when it is indistinguishable from a legitimate
result.** ADR [0012](decisions/0012-enforcement-mechanisms.md) applies it to
three mechanisms that do not all land the same way.

**Reject an uncitable result at construction, not at render time.** A
`SearchHit` with neither `req_id` nor `doc_key` used to render as the literal
string `None`, and an anchor without a `doc_key` as `None#password-storage`.
Each looks like a citation and points nowhere, which is how a fabricated
reference reaches a security report. Validating in `__post_init__` puts the
error on whichever retriever built the incomplete row, rather than surfacing a
plausible-looking string to the consumer. Whatever your storage, a retrieval
layer that can emit an unresolvable citation will eventually emit one.

**Make citations reproducible, and if you cannot, say so.** Pinning is not
about tidiness. It is what separates "the tool told me ASVS V6.2.1 says X" from
"the model recalled that ASVS says something like X." The anti-goal stated
throughout this project is *silent fallback to recalled guidance* — the failure
where there is no way to tell from the output alone whether an answer came from
the corpus or from the model's memory. Reproducible citations are the mechanism
that makes the difference visible.

**Enumeration must refuse to truncate.** When a query is
completeness-shaped — every requirement at this level, every control in this
chapter — a partial answer that looks complete is worse than a large one. The
fix here was to make the response cheaper without making it partial: grouping
by chapter and section hoisted the repeated labels and cut the unfiltered
response from 140,698 to 103,134 characters, a 26.7% saving, with 58% of the
remainder being irreducible requirement text. When a response is genuinely too
large, the note the tool attaches is *directive* — it names the chapter ids and
the expected total, so an agent that has to split the work knows what a
complete split looks like.

**Measure the claim the architecture rests on.** The paraphrase claim in
section 3 was asserted, believed, and load-bearing for a storage decision
before anyone counted how often "brute force" appears in the corpus. It appears
34 times, and counting it inverted the architecture. A smaller case from the
same record: the recommended chunk size of 400 tokens cut truncation hardest
(2.4%) but measurably degraded retrieval — hybrid mean rank 2.2 → 2.8 — so 512
was chosen instead, at 4.6% truncation and no rank regression. In both cases
the stated recommendation was wrong and the measurement was cheap. (Those three
truncation figures are one experiment on the pre-CWE 2,894-chunk corpus and are
quoted as measured; on the shipped index 512 now truncates **1.4%**, 68 chunks.
Most of the original 4.6% turned out to be a defect rather than a property --
`_split_oversized` never size-checked its final block, so whether a document
split depended on where its largest paragraph sat. Restating one arm of a
comparison from a different corpus would break the comparison, which is the
point of the anecdote.)
