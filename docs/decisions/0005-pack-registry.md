# 5. Pack registry, not hardcoded KBs

## Status

Accepted.

## Context

The server needs to hold two structurally different kinds of OWASP content —
ASVS's enumerable, leveled requirements and the Cheat Sheet Series' freeform
documents — and expose retrieval and navigation over both. The straightforward
version of this hardcodes "ASVS" and "cheat sheets" as named concepts
throughout the schema and the server: an `asvs_requirements` table, a
`cheatsheet_docs` table, tools that know the names of both by construction.

## Decision

Model every knowledge base as a **pack** — one row in a generic `packs` table
carrying a `type` of either `checklist` (an enumerable, leveled requirement
set) or `corpus` (a document collection navigated by heading) — rather than
naming "ASVS" or "cheat sheets" anywhere in the schema or the server. `asvs`
and `cheatsheets` are simply the two pack names that happen to exist today,
distinguished from any future pack only by their row in `packs` and the
`type` it carries. `owasp_checklist` is the one tool gated by `type`; every
other tool operates identically regardless of which pack a row came from,
because all content ultimately resolves through `chunks`.

## Consequences

- **Adding a pack needs no server change** — the entire path is in `ingest/`
  (a lock entry, an ingest module, a `build.py` registration, fixtures) as
  detailed in [docs/kb-packs.md](../kb-packs.md). A correctly-shaped new pack
  is immediately queryable by every tool that applies to its type, with zero
  changes to `server/tools.py`, `server/prompts.py`, or any skill.
- **Both existing packs deliberately live in one server, not two.** This was
  a real choice, not an accident of scope: OWASP's own `IndexASVS.md` already
  joins the two knowledge bases upstream, mapping ASVS sections to the cheat
  sheets that explain how to satisfy them. Splitting ASVS and the Cheat Sheet
  Series into two separate MCP servers would have thrown that join away, or
  forced an agent to call two servers and correlate the results itself. The
  `links` table's `guidance` edges exist precisely to preserve that join, and
  `owasp_related` is built specifically to answer "which requirement applies,
  and which cheat sheet says how to satisfy it" — measured to be the
  highest-value query the system can answer (see
  `tests/test_retrieval_quality.py::test_requirement_lookup_reaches_its_guidance`,
  labeled in its own docstring as exactly that). One server, two packs, one
  join between them, is the design that keeps that query answerable in a
  single tool call.

## Note, 2026-07-28: the registry now holds a pack that is not OWASP's

Added with the CWE pack (0.10.0). The decision above stands unchanged; two of its
framings were too narrow, and that is worth recording rather than editing away.

**"Model every knowledge base as a pack" was written about OWASP content, and the
first pack added under it was MITRE's.** Every sentence above says "OWASP content",
"OWASP projects", "which OWASP project next". The generic registry turned out to be
more general than the reason given for building it: `cwe` is a `packs` row like any
other, carrying its own `license` (`LicenseRef-CWE-TOU`) and `source_url`, and
nothing in the schema or the registry had to learn that one upstream is not OWASP.
That is the design working. But a reader of this ADR alone would conclude the
server serves only OWASP content, and since 0.10.0 it does not — CWE is MITRE's,
and it is here because ASVS maps to it. The framing, not the mechanism, was wrong.

**`type` was described as "either `checklist` or `corpus`", and there are now
three.** `catalogue` — keyed entries plus a relationship graph — was added to
`PACK_TYPES` and to the `packs.type` CHECK constraint. The two-value framing read as
a closed set; it was an open one with two members.

**"Adding a pack needs no server change" held for two packs and did not hold for the
third.** This is the consequence above that CWE falsified, and it is the useful part
of this note. CWE satisfied the pack contract in full — lock entry, ingest module,
`build.py` registration, fixtures — and was still not fully queryable, because its
structure is a graph and `owasp_related` disambiguates its `id` argument by counting
dots in an ASVS requirement id. Three new tools were needed (`cwe_get`,
`cwe_search`, `cwe_related`) and two new `Kb` methods. No *existing* tool or `Kb`
method changed, which is the part of the claim that survived. The corrected version:
a new pack of an **existing shape** needs no server change; a new *shape* needs
tools that can reach it, and the contract does not make that free. See
[docs/kb-packs.md](../kb-packs.md) for the current three-type table.

**Consequence for the image tag.** The content-pinned tag scheme was
`<variant>-asvs<version>-cs<date>`, naming two packs because there were two. With a
third pack whose ids are now directly citable through `cwe_get`, a CWE release bump
would have produced a byte-different index under an identical tag, defeating the
reproducibility the tag exists for. The scheme is now
`<variant>-asvs<version>-cs<date>-cwe<version>`. ADRs 0003 and 0004 quote the older
two-pack form; they are not wrong, they are dated.
