# Tools

Six MCP tools, all built in `server/tools.py` from methods on `core/kb.Kb`.
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
     "license": "CC-BY-SA-4.0"}
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
- `pack` — restrict to one pack (`"asvs"` or `"cheatsheets"`). Omit to search
  both.
- `level` — ASVS level `"1"`, `"2"`, or `"3"`. Applies to requirement hits
  only; cheat sheet hits are unaffected since they carry no level.
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
- Unknown `pack` name → `{"error": "unknown pack 'xyz'; available packs: asvs, cheatsheets"}`.
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
                 level: str | None = None) -> dict
```

Enumerates requirements from a `checklist` pack, filtered by any combination
of `chapter` (`"V6"`), `section` (`"V6.2"`), `req_id` (`"V6.2.1"`), and `level`
(`"1"`/`"2"`/`"3"`). Rows come back in numeric-aware chapter/section/id order
(`V10` after `V9`, not before `V2`) rather than lexical order, since lexical
order would silently corrupt any gap report that assumes ascending ids.

**Return shape:**
```json
{
  "pack": "asvs", "pack_version": "5.0.0", "count": 183,
  "requirements": [
    {"req_id": "V6.2.1", "level": "2", "chapter": "V6", "chapter_name": "Cryptography",
     "section": "V6.2", "section_name": "Algorithms", "text": "..."}
  ]
}
```

**No truncation.** Unlike `owasp_search` and `owasp_get`, this response is
never cut short: a gap report or assessment needs every applicable
requirement, and silently dropping rows from a compliance enumeration is a
worse failure than a large response. Measured, the full unfiltered ASVS
enumeration is roughly **140,000 characters**. Rather than truncate it, a
response with more than 100 rows carries an additional `"note"` field steering
the caller toward a chapter- or section-at-a-time workflow (`chapter='V6'`,
`section='V6.2'`) instead of silently sampling a small subset of a
compliance-relevant list.

**Error cases:**
- Unknown `pack` → same message as `owasp_search`.
- `pack` is `corpus`-typed → `{"error": "pack 'cheatsheets' is of type 'corpus'; owasp_checklist only applies to checklist packs. Use owasp_search or owasp_outline for corpus packs."}`.

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
