# 1. MCP for knowledge distribution

## Status

Accepted.

## Context

`owasp-kb` needs to get ASVS and Cheat Sheet Series content in front of an AI
coding agent in a form the agent will actually use while it works, across at
least three different agents (Claude Code, Codex, OpenCode). Two shapes were
considered:

- **Markdown bundled directly in the plugin, searched with `grep`** — ship
  the fetched ASVS and Cheat Sheet Series markdown as plugin assets, and let
  the agent read/grep them directly with its existing file tools. No server,
  no protocol, no schema.
- **An MCP server exposing structured tools** — ingest the content once into
  an index, and expose search/navigation/enumeration as typed tool calls over
  MCP.

## Decision

Serve the content through an MCP server (`server/app.py`, six tools). Bundled
markdown searched with `grep` was rejected:

- **No ranking.** `grep` (or an agent's built-in file search) returns literal
  string matches with no relevance ordering. A query like "keep my users
  logged out after they close the tab" shares almost no vocabulary with
  `Session_Management_Cheat_Sheet.md`; a literal-match tool returns nothing
  useful, where BM25 alone gets the same query into the top few results.
- **Failed searches cost more tokens than the server does.** A grep that
  returns nothing, or returns twenty tangentially-matching files an agent must
  then read in full to find the relevant paragraph, burns far more context
  than a single ranked tool call bounded by `MAX_EXCERPT_CHARS`. The tool
  schema has a fixed, small, permanent cost; a failed literal search has an
  unbounded and repeated one.
- **No structure to exploit.** ASVS requirements, chapter/section hierarchy,
  cross-references to cheat sheets, CWEs, and NIST controls are all real
  relationships this project can encode once (the `links` table) and let six
  tools query cheaply forever. Grep over flat markdown has no way to express
  "what cheat sheet explains how to satisfy V6.2.1" as anything other than
  another unranked text search.

## Consequences

- Tool schemas are sent to the model on every turn regardless of whether they
  get used, so **this is a permanent context cost, not a one-time one** — it
  is why there are six tools and not sixteen, and why
  [docs/discoverability.md](../discoverability.md) exists at all: a server
  nobody calls is pure overhead for zero benefit.
- The plugin and the server **must version together**: skills reference tool
  names literally (`owasp_search`, `owasp_checklist`, ...), so a server
  release that renames or removes a tool breaks every skill that names it.
  `tests/test_packaging.py::test_skills_only_reference_real_tools` exists
  specifically to catch that drift before it ships — see ADR
  [0006](0006-monorepo.md).
