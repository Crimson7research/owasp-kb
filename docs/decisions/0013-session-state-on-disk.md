# 13. An assessment's working state lives on disk, not in context

## Status

Accepted.

## Context

An ASVS assessment accumulates more material than one agent's context can hold,
and it accumulated all of it on the wire.

Two measurements forced the change:

- **A realistic L2 roster submission is ~61,555 characters**, of which evidence
  alone is 47.2%. Correcting a single verdict meant re-sending all of it. One run
  did that three times.
- **The report was a single 120,895-character write.** Every other stage —
  inventory, refutation, finding, verification — left a durable result; the
  report depended on all of it surviving in one agent's context until that one
  write succeeded. It is larger than an `owasp_checklist(level='2')` response
  that had already proved undeliverable, and an interruption there loses the
  write while the material to redo it is spread across 151 subagent transcripts.

There was also no shared place to put anything. The exclusion list, the scope
inventory and the dispatch ledger each wanted somewhere durable, and each would
have invented its own convention.

## Decision

One directory per session, on the host, at:

```
${CLAUDE_CONFIG_DIR:-~/.claude}/owasp-kb/sessions/<session-id>/
```

| File | Written by | Read by |
|---|---|---|
| `excluded` | the skill, at scope | `block_excluded_reads.py` |
| `concerns` | the skill, when inventory agents go out | `gate_triage_on_inventory.py` |
| `inventory.md` | the main session, as agents return | triage, and the gate above |
| `pending.txt` | the main session, as agents go out and return | the main session, after a compaction |
| `findings.jsonl` | the main session, as verdicts settle | `owasp_roster` |
| `report/` | the main session, as material appears | `owasp-kb-report` |

Everything per-assessment shares one directory and one lifetime. The exclusion
list moved here from its own path specifically so a third convention would not
calcify.

**`findings.jsonl` is append-only, one JSON object per line.** A later line
supersedes an earlier one for the same `req_id`. That is the only place order
carries meaning, and it is amendment history rather than a tie-break: once
resolved, assembly sees one entry per `req_id` and stays order-independent.
Correcting a verdict costs 169 characters instead of 11,701, measured end to
end.

**`report/` holds numbered sections, merged programmatically.** The numeric
prefix carries the order, so a chapter roster can land when its orchestrator
returns rather than when its neighbours are ready. Ordering is numeric, not
lexicographic — `sorted()` on filenames puts `1000` before `201`, which would
reorder any report past a hundred sections and give no indication it had.

The merge refuses rather than producing a report that looks complete: on a
duplicate number, because one section would be dropped and nothing downstream
could tell; on a finding count that disagrees with the roster, because a finding
with no detail section is invisible; and on an empty directory, because an empty
report reads as an assessment result. Those refusals are the reason to do this
at all, and they are the easiest part to leave out.

### The mount is read-only, and that is not a compromise

The server runs in a container with no filesystem access and no way to learn the
session id. The host directory is mounted at `/state`:

```
-v "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb:/state:ro"
```

Read-only is a smaller change than it first appears: the image gains read access
to one directory and still cannot write anything on the host. It also sidesteps
a uid mismatch, since the container runs as 10001 and the directory belongs to
whoever runs Claude Code. `--network none` is unchanged.

The consequence is that **anything which writes runs on the host.**
`owasp-kb-report` is a host script in the plugin's `bin/` for exactly this
reason — the state mount is read-only and the target repository is not mounted
at all, so nothing in the container can write the report.

### Why the command is `sh -c` and not a wrapper

The `mkdir` and the mount path both need shell expansion, so `.mcp.json` runs
`sh -c`. This was a wrapper script on the plugin's `bin/` first, and it did not
work: that directory is on `PATH` for shell tools, but the MCP subprocess does
not inherit it. `${CLAUDE_PLUGIN_ROOT}` would have been no better — no installed
plugin relies on `${...}` expansion in `.mcp.json`, and it would fail silently
rather than loudly. Swapping one unverified mechanism for another is not a fix.

`sh` is resolvable anywhere and expands `$HOME` itself, so the command depends
on neither `PATH` lookup nor harness expansion. The mount, `--network none`, the
read-only flag and the `mkdir` are all pinned by tests against the command in
`.mcp.json`, which is where the behaviour lives.

The `mkdir` is load-bearing: a bind mount whose source is missing is created by
the daemon and owned by root, which the agent could then not write to.

## Consequences

- **Loading fails closed, unlike the exclusion hook.** A missing `findings.jsonl`
  read as an empty set would produce a roster reporting every requirement as
  `INSUFFICIENT EVIDENCE`, which reads as an assessment result rather than as a
  missing file. ADR [0012](0012-enforcement-mechanisms.md) covers why the two
  directions differ.

- **A run interrupted late keeps most of its report.** Sections are durable as
  soon as they are written, and both skills carry a table of the earliest point
  each can be written — title at scope, trust boundaries at inventory,
  exemptions at the refuters, each chapter roster when *that* orchestrator
  returns, each finding when *that* verifier returns. Only the summary must come
  last, because it quotes the roster's final counts.

- **Writing order is free, and one run did not use it.** All seventeen chapter
  rosters were written in one batch though the ledger recorded two orchestrators
  as returned, and fifteen findings were written serially afterwards — 17 minutes
  of a 64-minute run spent writing the report after verification had finished.
  The numeric prefix exists so that none of that has to be serial.

- **State is per-session and never enters the target repository.** A session that
  ran no assessment has no directory, which is what makes the hooks in ADR 0012
  safe to ship to everyone.

- **Nothing garbage-collects `sessions/`.** Directories accumulate under
  `~/.claude/owasp-kb/`. They are small — text and JSONL — but no mechanism
  removes them, and the durability the design depends on is the same property
  that makes them persist.

- **Inline findings still work.** The file is an additional path, not a
  replacement, so a caller that passes verdicts directly to `owasp_roster` is
  unaffected.
