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
