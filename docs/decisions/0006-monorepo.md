# 6. Monorepo

## Status

Accepted.

## Context

The project has three genuinely different kinds of artefact: the ingest
pipeline and MCP server (`src/owasp_kb/`), the Claude Code plugin and skills
(`plugins/owasp-kb/`), and the install tooling for other agents
(`install/`). These could live in separate repositories — a server repo, a
plugin repo, an installer repo — each with its own release cadence, or
together in one.

## Decision

Keep all of it in a single repository, with a single marketplace manifest
(`.claude-plugin/marketplace.json`) pointing at the one plugin directory this
repo also builds the server from.

The rationale is not merely convenience: the four skills reference MCP tool
names **literally, as plain text** — `owasp_search`, `owasp_checklist`,
`owasp_related`, and so on appear directly in each `SKILL.md` body, because a
skill's whole job is to tell an agent exactly which tool to call. That means
the plugin and the server are coupled by contract whether or not the
repository layout admits it: a server release that renames or removes a tool
silently breaks every skill that names it, and a skill written against a tool
that does not exist is worse than useless — it actively misleads an agent
into calling something that will error or, worse, silently do the wrong
thing. Splitting the two into separate repositories would not remove this
coupling, only hide it behind two release processes that have no way to
notice they have drifted apart. A monorepo makes the coupling visible and
lets one commit, one CI run, and one marketplace URL keep both sides
consistent by construction.

## Consequences

- Installing the plugin (`/plugin marketplace add`, `/plugin install`) or
  either agent's install script always gets a plugin and a server that were
  built and tested together, from one commit.
- **The coupling is not automatic just because the code lives in one
  repository** — nothing about a monorepo layout by itself prevents someone
  editing `server/tools.py` to rename a tool without updating the skill that
  names it. That is exactly why
  `tests/test_packaging.py::test_skills_only_reference_real_tools` exists: it
  extracts every `owasp_\w+`/`kb_info`-shaped token from every skill body and
  asserts each one is a real tool name, so a rename that breaks a skill fails
  CI immediately rather than shipping and breaking silently at some agent's
  runtime.
