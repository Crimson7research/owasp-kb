# Tools

Ten MCP tools, built in `server/tools.py`. Nine wrap methods on `core/kb.Kb`;
the tenth, `owasp_roster`, wraps `core/roster.build_roster` instead — it
assembles verdicts an assessment already produced rather than reading the
knowledge base itself.

Three of the ten (`cwe_get`, `cwe_search`, `cwe_related`) address the CWE pack
specifically. The other seven are pack-agnostic. CWE is MITRE's, not OWASP's, and
is in this server because ASVS maps its requirements to CWE ids — see
[docs/licensing.md](licensing.md).
Every tool description is written as a trigger list rather than a summary —
see [docs/discoverability.md](discoverability.md) for why. This document
covers the mechanics: signatures, argument semantics, return shapes, error
cases, and a worked example for each.

## Size caps

```
MAX_EXCERPT_CHARS = 1200   # owasp_search hit excerpts
MAX_GET_CHARS      = 30_000  # owasp_get document/section text
```

Both cap what a single tool call can push into an agent's context. `owasp_get`
is the one that matters most in practice: the largest cheat sheet document is
37,296 characters, so fetching a whole document can be truncated —
`owasp_outline` exists precisely so an agent fetches one section by anchor
instead of hitting that cap. Truncated text is suffixed with
`\n[truncated at N characters]` rather than silently cut, so an agent (or a
human reading a transcript) can tell truncation happened.

`owasp_checklist` has **no cap** — see its section below for why that is
deliberate rather than an oversight.

## `kb_info`

```
kb_info() -> dict
```

No arguments. Returns which packs are loaded, their versions, and the active
retrieval mode. Call this first when unsure what content is available, or
whenever a citation needs an exact version string.

**Return shape:**
```json
{
  "retrieval_mode": "hybrid",
  "packs": [
    {"name": "asvs", "type": "checklist", "version": "5.0.0",
     "commit_sha": null, "license": "CC-BY-SA-4.0"},
    {"name": "cheatsheets", "type": "corpus", "version": "20260724",
     "commit_sha": "7d1c2d3daf632206e8f2c685214c699ff8f11938",
     "license": "CC-BY-SA-4.0"},
    {"name": "cwe", "type": "catalogue", "version": "4.20",
     "commit_sha": null, "license": "LicenseRef-CWE-TOU"}
  ]
}
```

No error cases — it only reads from tables guaranteed to exist in any built
index.

## `owasp_search`

```
owasp_search(query: str, pack: str | None = None, level: str | None = None,
             limit: int = 8) -> dict
```

- `query` — natural-language description of the security topic. Free text;
  internally reduced to a set of search terms (stopwords stripped for the
  lexical half — see [docs/build.md](build.md) and
  `core/retrieval/lexical.to_fts_query`).
- `pack` — restrict to one pack (`"aisvs"`, `"asvs"`, `"cheatsheets"`, `"cwe"`
  or `"masvs"`). Omit to search all five. `cwe_search` is exactly this call with
  `pack="cwe"`.
- `level` — level `"1"`, `"2"`, or `"3"`. ASVS and AISVS have levels, and
  AISVS's align with ASVS's one to one; MASVS has none. Cheat sheet and CWE
  hits are unaffected since they carry no level, and naming a level-less
  checklist pack (`pack="masvs"`) together with `level` is refused rather than
  silently matching nothing. Omitting `pack`, a `level` filter excludes
  level-less packs by construction — asking for L2 is asking ASVS and AISVS.
- `limit` — maximum hits returned (default 8).

**Return shape (a hit):**
```json
{
  "citation": "ASVS 5.0.0 V6.2.1",
  "pack": "asvs",
  "req_id": "V6.2.1",
  "doc_key": null,
  "anchor": null,
  "heading_path": "Stored Cryptography > Algorithms",
  "excerpt": "..."
}
```
For a cheat sheet hit, `req_id` is `null` and `doc_key`/`anchor` are set
instead; `citation` is `"{doc_key}#{anchor}"` in that case.

**Error cases:**
- Unknown `pack` name → `{"error": "unknown pack 'xyz'; available packs: aisvs, asvs, cheatsheets, cwe, masvs"}`.
- **No match → `{"hits": [], "message": "..."}`, not `{"hits": []}` and never
  a bare `[]`.** This is deliberate and worth stating explicitly: an agent
  that receives `[]` for a search reads it as "no security requirements apply
  here," which is a materially different and far more dangerous claim than
  "this particular query found nothing." `Kb.search` raises `LookupError` for
  the no-match case specifically so the tool layer can attach that
  disambiguating message rather than let the distinction collapse into an
  empty array. The message also suggests trying different wording — genuinely
  off-topic queries (`"zzzznotpresentanywhere"`) and paraphrases that just
  didn't hit any indexed vocabulary look identical to the retriever, and only
  the caller can tell which one it was.

**Worked example:**
```
owasp_search("how do I store passwords", limit=3)
```
```json
{
  "hits": [
    {"citation": "Password_Storage_Cheat_Sheet#introduction", "pack": "cheatsheets",
     "req_id": null, "doc_key": "Password_Storage_Cheat_Sheet",
     "anchor": "introduction", "heading_path": "Password Storage Cheat Sheet > Introduction",
     "excerpt": "..."},
    {"citation": "ASVS 5.0.0 V6.2.1", "pack": "asvs", "req_id": "V6.2.1",
     "doc_key": null, "anchor": null,
     "heading_path": "Cryptographic Verification > Stored Cryptography", "excerpt": "..."}
  ]
}
```

## `owasp_outline`

```
owasp_outline(doc_key: str) -> dict
```

`doc_key` is a document key — a cheat sheet filename stem (e.g.
`Password_Storage_Cheat_Sheet`) or an ASVS chapter key (e.g. `V6`). Returns the
heading tree so a caller can pick one anchor instead of fetching the whole
document with `owasp_get`.

**Return shape:**
```json
{
  "doc_key": "Password_Storage_Cheat_Sheet",
  "sections": [
    {"anchor": "introduction", "heading": "Introduction", "depth": 2},
    {"anchor": "general-guidance", "heading": "General Guidance", "depth": 2}
  ]
}
```

**Error case:** unknown `doc_key` → `{"error": "unknown doc_key 'xyz'. Closest matches: ..."}`
(fuzzy-matched via `difflib.get_close_matches` against every real `doc_key`,
so a near-miss like a wrong underscore gets a usable hint rather than a bare
failure).

## `owasp_get`

```
owasp_get(doc_key: str, anchor: str | None = None) -> dict
```

Returns the full text of a document, or one section when `anchor` is given.
Prefer passing an anchor from `owasp_outline` — the largest cheat sheet is
37,296 characters and whole-document fetches are subject to `MAX_GET_CHARS`.

**Return shape:**
```json
{"citation": "Password_Storage_Cheat_Sheet#introduction", "text": "..."}
```
`citation` is `doc_key` alone when `anchor` is omitted.

**Error cases:**
- Unknown `doc_key` → same fuzzy-matched error as `owasp_outline`.
- Unknown `anchor` for a known `doc_key` → `{"error": "unknown anchor 'xyz' in '...'. Available anchors: ..."}`,
  listing every real anchor for that document.

## `owasp_checklist`

```
owasp_checklist(pack: str = "asvs", chapter: str | None = None,
                 section: str | None = None, req_id: str | None = None,
                 level: str | None = None, level_exact: str | None = None) -> dict
```

Enumerates requirements from a `checklist` pack (`asvs`, `masvs` or `aisvs`), filtered
by any combination of `chapter` (`"V6"`), `section` (`"V6.2"`), and `req_id`
(`"V6.2.1"`). Rows come back in ascending chapter/section/id order (`V10`
after `V9`, not before `V2`, for ASVS) rather than lexical order, since
lexical order would silently corrupt any gap report that assumes ascending
ids. The guarantee holds for any pack, but the mechanism behind it changed:
ordering comes from `requirements.ord`, a per-pack, dense-from-0 ordinal each
ingest module assigns as it inserts rows (`UNIQUE (pack_id, ord)`), not from
parsing id syntax in SQL. The `ORDER BY ord` this replaced was an expression
that read ASVS's `V<n>.<n>.<n>` shape directly and evaluated to `0` for any
other id shape — which would have silently ordered a second checklist pack by
table-scan order the moment one existed.

**Levels belong to ASVS and AISVS, not every checklist pack.** Where a pack has levels,
`level` is **cumulative**, matching how ASVS itself defines its levels:
`level="2"` returns every requirement an L2 assessment must verify — all L1
requirements plus everything newly introduced at L2 (253 of 345 in ASVS
5.0.0), not only the 183 individually tagged L2. Returning just the tagged
set would silently drop password minimums and every other L1 control from a
report labelled L2. `level="1"` returns 70; `level="3"` returns all 345.
`level_exact` is the rarer single-tier query — `level_exact="2"` returns
exactly the 183 requirements tagged L2, nothing inherited from L1. Passing
both `level` and `level_exact` is an error (see below). AISVS 1.01 works
the same way: `level="1"`, `"2"` and `"3"` return 57, 167 and 213, and its ids
are `C`-prefixed (`chapter="C10"`, `section="C10.2"`, `req_id="C10.2.2"`).

MASVS defines no levels at all: its 24 controls come back with no `"L"` key,
and passing `level` or `level_exact` with `pack="masvs"` is an error naming
the pack (see below), not a filter that quietly matches nothing — the same
reasoning `owasp_search` documents for refusing a level on a level-less pack.

**Return shape**, grouped by chapter then section so each name is stated once
rather than once per row (measured 27% smaller on the full 345-requirement
enumeration, with no row dropped):
```json
{
  "pack": "asvs", "pack_version": "5.0.0", "count": 345,
  "chapters": [
    {
      "id": "V6", "name": "Authentication",
      "sections": [
        {
          "id": "V6.2", "name": "Password Security",
          "requirements": [
            {"id": "V6.2.1", "L": "1",
             "text": "Verify that user set passwords are at least 8 characters..."}
          ]
        }
      ]
    }
  ]
}
```
Walk `chapters[].sections[].requirements[]`; the top-level `count` is the total
and nothing is ever truncated.

A level-less pack's shape is worth showing rather than just describing, since
the absence of a key reads very differently in prose than in the JSON an agent
actually parses (`pack="masvs"`, two-tier — the chapter and section are the
same group):
```json
{
  "pack": "masvs", "pack_version": "2.1.0", "count": 24,
  "chapters": [
    {
      "id": "MASVS-STORAGE", "name": "Storage",
      "sections": [
        {
          "id": "MASVS-STORAGE", "name": "Storage",
          "requirements": [
            {"id": "MASVS-STORAGE-1",
             "text": "The app securely stores sensitive data..."}
          ]
        }
      ]
    }
  ]
}
```
No `"L"` key on the requirement — omitted, not `null`.

**No truncation.** Unlike `owasp_search` and `owasp_get`, this response is
never cut short: a gap report or assessment needs every applicable
requirement, and silently dropping rows from a compliance enumeration is a
worse failure than a large response. Measured, the full unfiltered ASVS
enumeration is roughly **140,000 characters**. Rather than truncate it, a
response with more than 100 rows carries an additional `"note"` field naming
every chapter id and steering the caller toward calling once per chapter and
keeping a running tally that must sum to the total, instead of silently
sampling a small subset of a compliance-relevant list.

**Error cases:**
- Unknown `pack` → same message as `owasp_search`.
- `pack` is `corpus`-typed → `{"error": "pack 'cheatsheets' is of type 'corpus'; owasp_checklist only applies to checklist packs. Use owasp_search or owasp_outline for corpus packs."}`.
- Both `level` and `level_exact` given → `{"error": "pass level or level_exact, not both: level is cumulative (L2 = L1 + L2), level_exact is a single tier"}`.
- `level` or `level_exact` given for a pack with no levels (`pack="masvs"`) →
  `{"error": "pack 'masvs' defines no levels, so filtering by one would return an empty list, not a filtered one -- an agent reads [] as 'nothing in this pack meets that level', which is a different and far more dangerous claim than 'this pack has no levels'. Same reasoning Kb.search documents for raising LookupError instead of returning []. Omit level and level_exact."}`.

## `owasp_related`

```
owasp_related(id: str, rel: str | None = None) -> dict
```

`id` accepts three shapes, disambiguated by dot count:

- a **requirement id** (`"V6.2.1"`, three dot-separated parts after the
  chapter letter),
- an ASVS **section or chapter id** (`"V6.2"` or `"V6"`),
- or a **cheat sheet `doc_key`** (`"Authentication_Cheat_Sheet"`).

`rel` optionally restricts to one relationship type: `guidance`, `cwe`,
`supersedes`, or `nist`.

**A requirement inherits its section's (and chapter's) guidance edges.** This
is the single most load-bearing behavior in the tool, and it exists because of
an asymmetry between how the upstream data is shaped and how agents actually
ask questions: `IndexASVS.md` maps cheat sheets to ASVS **sections**
(`V6.2`), never to individual requirements, but an agent investigating a
specific requirement asks `owasp_related("V6.2.1")`, not `owasp_related("V6.2")`.
`Kb.related` expands any three-part requirement id into
`[id, "chapter.section", "chapter"]` and queries all three as `from_id`
candidates before returning. Without this roll-up, the highest-value query in
the whole system — "which cheat sheet explains how to satisfy this
requirement" — would return nothing for the overwhelming majority of
requirement-level lookups, since almost no `guidance` edge is recorded at the
requirement level in the first place.

**Return shape:**
```json
{
  "id": "V6.2.1",
  "edges": [
    {"rel": "cwe", "to_kind": "cwe", "to_id": "CWE-326", "source": "v5.0.be_cwe_mapping.json"},
    {"rel": "guidance", "to_kind": "doc", "to_id": "Cryptographic_Storage_Cheat_Sheet",
     "source": "IndexASVS.md"},
    {"rel": "nist", "to_kind": "nist", "to_id": "NIST SP 800-63B 5.1.1.1", "source": "nist.md"},
    {"rel": "supersedes", "to_kind": "requirement", "to_id": "4.0.3-6.2.1",
     "source": "mapping_v5.0.0_to_v4.0.3.yml"}
  ]
}
```

No error cases raised at the tool layer: an unknown `id` simply returns
`{"id": "...", "edges": []}` (querying `links` with candidate ids that match
nothing is not itself an error the way an unknown `pack` or `doc_key` is,
since `owasp_related` is also legitimately callable with a fresh, uncached
`doc_key` from a search hit — treating that as a hard failure would be overly
strict for a tool meant to be chained after `owasp_search`).

## The three CWE tools

These three exist because `owasp_related(req_id, rel='cwe')` answers "which CWE id
does OWASP map to this requirement" and nothing answered "what is this CWE id". Of
95 CWE ids cited in findings in one real assessment, 42 were not in OWASP's mapping,
and the mapping reaches only 204 of 345 requirements — so the id an agent ends up
citing is frequently one it chose itself. Every tool description in this group is
written to be read before the citation is made, not after.

Where these tool docstrings and this document disagree, **the docstring is
authoritative**: it is the text the agent actually reads.

### `cwe_get`

```
cwe_get(entry_id: str) -> dict
```

One entry by id: `kind` (`weakness` or `category`), `name`, `abstraction`, `status`,
`description`, `extended_description`.

**An id absent from the catalogue is an error, not an empty result.** This is the
opposite of `owasp_related` and deliberately so: the catalogue's id space is closed
and enumerable, so `CWE-99999` is not a coverage gap, it is a wrong number. The
`KeyError` names the id and says that Views are deliberately not ingested (a View is
a perspective on the catalogue, not a definition of a weakness), so a caller can tell
"I cited something that does not exist" from "this pack does not carry that kind of
entry".

**Return shape:**
```json
{
  "entry_id": "CWE-789",
  "kind": "weakness",
  "name": "Memory Allocation with Excessive Size Value",
  "abstraction": "Variant",
  "status": "Draft",
  "description": "The product allocates memory based on an untrusted, large size value, but it does not ensure that the size is within expected limits, allowing arbitrary amounts of memory to be allocated.",
  "extended_description": "..."
}
```

Two fields carry more weight than they look like they do:

- **`status`.** `CWE-320` "Key Management Errors" is `Obsolete`, and **8 ASVS
  requirements map to it**. Substituting a live, specific weakness there is an
  improvement a report can now evidence rather than assert.
- **`abstraction`** — `Pillar`, `Class`, `Base`, `Variant` or `Compound`, and
  **`null` for a category**, which has no level. It is stated rather than omitted so
  that a comparison between two cited ids can see that one of them has nothing to
  compare.

No truncation. Measured on CWE 4.20 the longest `description` is 505 characters and
the longest `extended_description` 3,677, so a whole entry is smaller than one
cheat-sheet section.

### `cwe_search`

```
cwe_search(query: str, limit: int = 8) -> dict
```

Lexical search restricted to the CWE pack — for when the defect is understood but
the id is not known. OWASP's mapping is silent for **141 of 345** requirements, which
is the case this exists for.

**Return shape:**
```json
{
  "hits": [
    {"entry_id": "CWE-789", "citation": "CWE-789#description",
     "heading_path": "CWE-789: Memory Allocation with Excessive Size Value > Description",
     "excerpt": "The product allocates memory based on an untrusted, large size value..."}
  ]
}
```

`entry_id` is what you cite; `cwe_get` on it gives the `abstraction` and `status` the
citation needs. Excerpts are capped at `MAX_EXCERPT_CHARS`, as in `owasp_search`.

**A miss returns `{"hits": [], "message": ...}` — an empty list *with* a message**,
never a bare empty list, because "no results" on its own reads to an agent as "no
such weakness exists". An index built without the CWE pack is reported as an error
instead, for the same reason: that is a fact about the build, not about the query.

Hits are lexically ranked and **near-ties are common** — two entries can score
identically and order arbitrarily between them. Read the top few and choose on the
names and descriptions rather than on rank.

### `cwe_related`

```
cwe_related(entry_id: str, ancestors: bool = False) -> dict
```

The entry's edges: `cwe_child` (ChildOf, toward the abstract), `cwe_peer` (see below —
**not** PeerOf) and `cwe_member` (a Category's members). With `ancestors=True`, the
whole ChildOf chain nearest-first rather than direct parents only.

**`cwe_peer` is a catch-all and its name is misleading.** The ingest maps every
non-`ChildOf` `Related_Weakness` nature onto it, so "peer" is the minority reading.
Of the 284 `cwe_peer` edges in CWE 4.20:

| Nature | Edges | Share | What it means |
|---|---|---|---|
| `CanPrecede` | 143 | 50.4% | A **sequence**: this weakness can lead to that one |
| `PeerOf` | 98 | 34.5% | Similar, at the same level |
| `CanAlsoBe` | 27 | 9.5% | The same defect is sometimes classified as that one |
| `Requires` | 13 | 4.6% | That weakness must also be present for this one to matter |
| `StartsWith` | 3 | 1.1% | A sequence, at its start |

The plurality is a *directed* relation, and the edge is stored in one direction only,
so a `cwe_peer` from A to B does **not** imply one from B to A. An agent that reads
`cwe_peer` as "these are equivalent, either id will do" is wrong half the time, and
wrong about direction more often than that. Read it as "related somehow — go read
both entries", and do not substitute one id for the other on the strength of it.
The nature itself is not stored: if you need it, the entry text is the only source.

**Return shape** (`CWE-789`, `ancestors=True`):
```json
{
  "entry_id": "CWE-789",
  "ancestors": true,
  "truncated": false,
  "edges": [
    {"rel": "cwe_child", "to_kind": "cwe", "to_id": "CWE-770", "abstraction": "Base", "source": "cwec_v4.20.xml"},
    {"rel": "cwe_child", "to_kind": "cwe", "to_id": "CWE-400", "abstraction": "Class", "source": "cwec_v4.20.xml"},
    {"rel": "cwe_child", "to_kind": "cwe", "to_id": "CWE-665", "abstraction": "Class", "source": "cwec_v4.20.xml"},
    {"rel": "cwe_child", "to_kind": "cwe", "to_id": "CWE-664", "abstraction": "Pillar", "source": "cwec_v4.20.xml"}
  ]
}
```

`abstraction` on an edge is the **target's** (`to_id`), not the id you asked about,
and is `null` where the target lies outside this catalogue. The join to
`catalogue_entries` is a LEFT JOIN for that reason: `CWE-320`'s `Has_Member` targets
are not all ingested, and an inner join would return nothing at all for it rather
than four member edges with a null abstraction.

`truncated` says whether the ancestor walk stopped before running out of ancestors.
It is `false` for every entry in the published catalogue: the walk is bounded by
`MAX_ANCESTOR_DEPTH = 20` (`core/kb.py`) and the deepest real walk is **5 levels**, so
the cap has four times the headroom it needs. **If it is ever `true`, the chain is
missing its coarsest end** — which is exactly where the Pillar sits, so a
shared-ancestor comparison read off a truncated chain is unsound in the one direction
that matters.

"5 levels" is BFS depth, the thing the cap actually bounds; the longest simple
`ChildOf` path happens to be 5 as well, but those are different measurements and
"chain length" names neither. Mean depth is 2.39 over the 969 Weaknesses. For scale on
how little slack a smaller cap would leave: at 4 the walk truncates for 19 entries, at
3 for 107.

**What the tool does not decide.** Whether a self-chosen id refines a mapped one,
substitutes for it, or is simply unrelated is the caller's judgement. The measured
asymmetry to reason with: **28% of weakness pairs share some ancestor and only 4%
share a non-Pillar one**, so a shared `Pillar` means almost nothing while a shared
`Base` or `Class` is meaningful. A report should say which it found.

Those two figures are random pairs of the 969 Weaknesses, ancestors taken
transitively over `ChildOf` only, a node excluded from its own ancestor set — stated
because the pair they replace (35%/5%) could not be reproduced under any methodology,
precisely because none had been recorded. Rounded on purpose: a tenth of a percent
would imply the sampling was pinned more tightly than it is.

As with `cwe_get`, an id absent from the catalogue raises rather than returning `[]`
— an empty edge list must be readable as "this entry records no relationships" and
never as "no such id".

## `owasp_roster`

```
owasp_roster(pack: str = "asvs", chapter_states: dict | None = None,
             findings: list | None = None, excluded: list | None = None,
             level: str | None = None, require_verification: bool = True,
             detail: bool = False) -> dict
```

Assembles the verdicts an assessment produced into a complete, checked
roster. Call this at the end of an assessment instead of tallying by hand:
every requirement in scope lands in exactly one of seven verdicts, and one you
never reported a finding for becomes `INSUFFICIENT EVIDENCE` rather than
silently vanishing. Unlike the other nine tools, it does not read the
knowledge base for content — it takes the verdicts the caller already
determined and checks them for completeness and internal consistency. It
wraps `core/roster.build_roster`, not a method on `Kb`.

- `pack` — the `checklist` pack the requirements belong to (`"asvs"`).
- `chapter_states` — maps every chapter id in scope (`"V6"`) to `"APPLIES"` or
  an N/A verdict (`"N/A (verified)"` / `"N/A (unverified)"`). A chapter with
  no entry is an error — see below.
- `findings` — a list of dicts, each with `req_id`, `chapter`, `section`,
  `verdict` (one of the seven in `VERDICTS`), `evidence`, and optionally
  `file`, `line`, `cwe`, `remediation`, `trace`. Findings that share a
  `(file, line, cwe, verdict)` key are merged into one entry that covers every
  requirement any of them named — dropping the second would silently cost a
  chapter its coverage in the roster.
- `excluded` — paths to prior assessment reports found in the target. A
  finding whose `file`, `evidence`, `trace`, or `remediation` mentions one is
  rejected (see below); verdicts that assert nothing (`INSUFFICIENT EVIDENCE`,
  `N/A (unverified)`) are exempt from the scan, since they cannot import a
  conclusion they never drew.
- `level` — same cumulative ASVS level filter as `owasp_checklist`, applied to
  the scope the roster is checked against.
- `require_verification` — default `True`. A `GAP`, an `N/A (verified)` or an
  `INSUFFICIENT EVIDENCE (gap refuted)` asserts a checked outcome; without a
  `trace` from that check's adversary (`owasp-finding-verifier` for the first
  and the last, `owasp-exemption-refuter` for an `N/A (verified)`) the whole
  call is rejected. Record `GAP (unconfirmed)`, `N/A (unverified)` or plain
  `INSUFFICIENT EVIDENCE` instead when the check did not happen — those are
  the honest way past this, not a workaround. Pass `False` only for a
  deliberately quick, unverified pass; `verification_required: false` then
  appears in the response so a waived roster cannot look identical to a
  verified one.
- `detail` — default `False`. When `True`, adds an `entries` list with every
  requirement's own verdict and `finding_id`, not just the chapter/verdict
  totals.

**Return shape:**
```json
{
  "count": 3,
  "counts": {"GAP": 1, "MET": 1, "N/A (verified)": 1},
  "by_chapter": {
    "V6": {"GAP": 1, "MET": 1},
    "V2": {"N/A (verified)": 1}
  },
  "needs_attention": [],
  "findings": [
    {"id": 0, "verdict": "MET", "location": null, "cwe": null, "covers": ["V6.2.2"]},
    {"id": 1, "verdict": "GAP", "location": "app/auth/validators.py:41",
     "cwe": "CWE-521", "covers": ["V6.2.1"]},
    {"id": 2, "verdict": "N/A (verified)", "location": null, "cwe": null,
     "covers": ["V2.1.1"]}
  ],
  "complete": true,
  "verification_required": true
}
```
`findings` reports identity and resolution only — `id`, `verdict`, `location`
(`"{file}:{line}"` or `null`), `cwe`, and `covers` (the requirement ids the
merged finding accounts for). The `evidence`, `trace`, and `remediation` the
caller supplied are never echoed back: on a full assessment, echoing them was
measured at 72% of a 109,038-character response. `needs_attention` lists the
full entry (`req_id`, `chapter`, `section`, `level`, `verdict`, `finding_id`)
for every requirement landing on an `UNCERTAIN_VERDICTS` state
(`INSUFFICIENT EVIDENCE`, `INSUFFICIENT EVIDENCE (gap refuted)`,
`N/A (unverified)`, `GAP (unconfirmed)`) — the ones
a reader needs to look at regardless of `detail`. Pass `detail=True` for the
full per-requirement `entries` list instead of just chapter totals.

**Error cases.** All return `{"error": "..."}` rather than raising — real
messages, captured by calling `build_roster` directly:

- `excluded` passed as a bare string instead of a list (matched character by
  character, which rejects everything):
  ```
  excluded must be a list of paths, not a single string: a string is matched
  character by character and rejects everything. Pass ['prior-report.md'].
  ```
- `excluded` containing a non-string entry:
  ```
  excluded contains non-path entries [42, None]; every entry must be a path string
  ```
- A chapter present in the scope with no entry in `chapter_states`:
  ```
  no applicability state for chapter(s) V2; every chapter must be APPLIES or an N/A state
  ```
- A finding's `verdict` is not one of the seven in `VERDICTS`:
  ```
  unknown verdict 'MAYBE'; expected one of MET, GAP, N/A (verified), N/A (unverified), INSUFFICIENT EVIDENCE, INSUFFICIENT EVIDENCE (gap refuted), GAP (unconfirmed)
  ```
- A `GAP` (or `GAP (unconfirmed)`) with no `file`/`line` — a gap pointing
  nowhere is unactionable:
  ```
  GAP for V6.2.1 has no file/line; a gap with no location would reach the report pointing at nothing
  ```
- A finding citing a `req_id` outside the assessed scope:
  ```
  finding cites V9.9.9, which is not in the assessed set; scope and findings disagree
  ```
- A finding citing an excluded prior assessment report — the tool names the
  requirement and the path:
  ```
  1 requirement(s) cite an excluded prior assessment (V6.2.1 cites reports/prior-assessment.md). A prior report is someone else's conclusion, not evidence. Re-derive the finding from source, or drop it.
  ```
- `require_verification=True` (the default) and a `GAP`, an `N/A (verified)`,
  or an `INSUFFICIENT EVIDENCE (gap refuted)` carries no `trace` — grouped by
  which adversary is missing, listing only the fallbacks for the verdicts
  actually present:
  ```
  1 requirement(s) assert a checked outcome with no trace. Dispatch owasp-finding-verifier for V6.2.1, or record them as 'GAP (unconfirmed)' to mark them unverified.
  ```
  and, for an unverified exemption:
  ```
  1 requirement(s) assert a checked outcome with no trace. Dispatch owasp-exemption-refuter for V6.2.1, or record them as 'N/A (unverified)' to mark them unverified.
  ```
  and, for a refuted gap with no verifier — the adversary is the same as a
  plain `GAP`'s, but the fallback is the plain verdict, since no adversary was
  involved:
  ```
  1 requirement(s) assert a checked outcome with no trace. Dispatch owasp-finding-verifier for V6.2.1, or record them as 'INSUFFICIENT EVIDENCE' to mark them unverified.
  ```

**Worked example:**
```
owasp_roster(
    chapter_states={"V6": "APPLIES", "V2": "APPLIES"},
    findings=[
        {"req_id": "V6.2.2", "chapter": "V6", "section": "V6.2", "verdict": "MET",
         "evidence": "change-password endpoint requires current + new password"},
        {"req_id": "V6.2.1", "chapter": "V6", "section": "V6.2", "verdict": "GAP",
         "evidence": "minimum password length is 6, not 8",
         "file": "app/auth/validators.py", "line": 41, "cwe": "CWE-521",
         "remediation": "ASVS 5.0.0 V6.2.1: raise MIN_PASSWORD_LENGTH to 8",
         "trace": "owasp-finding-verifier: confirmed -- validators.py:41 sets MIN_PASSWORD_LENGTH = 6"},
        {"req_id": "V2.1.1", "chapter": "V2", "section": "V2.1", "verdict": "N/A (verified)",
         "evidence": "no input validation rule documentation exists or is required for this internal tool",
         "trace": "owasp-exemption-refuter: exemption_holds -- searched docs/, README.md, no validation-rule doc of any kind"},
    ],
)
```
returns the return-shape example above verbatim: `count: 3`, one `GAP`, one
`MET`, one `N/A (verified)`, `needs_attention: []`, and `complete: true` —
every requirement passed to it landed in exactly one verdict.
