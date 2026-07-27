---
name: verifying-a-reload
description: Verify that a plugin reload, MCP restart, or image rebuild actually reached the running system before trusting it. Use this whenever reloading the owasp-kb plugin, running /mcp, rebuilding the Docker image, bumping the plugin version, editing an agent definition, or asking any version of "did my change take effect?" — and especially before running an assessment or test that is supposed to prove a change works, because a stale server will produce a confident pass that means nothing.
---

# Verifying a reload

Three separate mechanisms decide whether a change reaches the running system, they fail
independently, and **every one of them reports success while serving stale code**. That is the
whole problem: the failure looks identical to the success.

## What each layer lies about

| Layer | Reports | Actually means |
|---|---|---|
| `/mcp` → "Reconnected" | the connection was re-established | says nothing about which image it connected to |
| `/plugin` → "already at the latest version" | the marketplace has no newer version | says nothing about whether the running session loaded it |
| plugin cache | — | keyed by version; without a `plugin.json` bump, edits never arrive |
| agent registry | — | loaded at session start; a new agent file is not dispatchable until reload |

The costly one: `/mcp` reported **"Reconnected to plugin:owasp-kb:owasp-kb"** while re-attaching
to an image built 9½ hours before the code change. The next step was an assessment intended to
prove that change worked. The stale server's `owasp_roster` accepted the input the new one
rejects, so the run would have completed cleanly and been read as proof — the test designed to
catch the bug would have been the thing fooled by it.

## The checks that actually work

Each one reads state rather than trusting a message.

**Is the image newer than the code?**

```bash
docker images owasp-kb --format '{{.Tag}}\t{{.CreatedAt}}' | grep '^full'
git log -1 --format='%h %ad' --date=iso -- src/
```

If the image timestamp is older than the last `src/` commit, the server is stale no matter what
`/mcp` said. Rebuild with `make build-full` — roughly 17 minutes, because it rebuilds the index
and embeddings before the image.

**Is the fix actually inside the image?** Timestamps are circumstantial; this is direct.

```bash
docker run --rm --network none --entrypoint python owasp-kb:full -c "
import inspect
from owasp_kb.core.roster import build_roster
print('excluded' in inspect.signature(build_roster).parameters)"
```

**Is the server serving it?** The tool schema is the evidence, not the reconnect message. Fetch
it with `ToolSearch` for the tool you changed and look for the new parameter or docstring text.
A reconnect that reports success while serving the old schema is the exact failure above.

**Will the cache pick up plugin changes?** `plugins/owasp-kb/.claude-plugin/plugin.json` must
have a bumped `version`. The cache lives at
`~/.claude/plugins/cache/owasp-kb/owasp-kb/<version>/` — check the new version directory exists
and contains your edit:

```bash
grep -c "the text you added" ~/.claude/plugins/cache/owasp-kb/owasp-kb/<version>/agents/*.md
```

**Are agent definitions live?** They load at session start. A newly written agent file is not
dispatchable until a plugin reload, and dispatching it fails with "Agent type not found" — which
is at least loud. Edits to an *existing* agent are the quiet case: the old text stays in effect.

## Order of operations

Code in `src/` changed → rebuild the image → reconnect MCP → verify the served schema.

Only prompts, skills or agent definitions changed → no rebuild needed → bump `plugin.json` →
reload the plugin → verify the cache directory.

Skipping the rebuild when `src/` changed is the common mistake, because the plugin reload
succeeds and everything looks current.

## Why not just trust the messages

Because they are honest about the wrong thing. "Reconnected" is true — a connection was made.
It carries no information about what is on the other end. The same holds for "already at the
latest version", which describes the marketplace rather than the session.

The general form, worth carrying beyond this repo: **when a success message and the thing you
care about are two different facts, verify the fact.** Read the served schema, the file on disk,
the timestamp — something the stale path could not produce.

## Related

`kb_info` returning `link_coverage` was useful for confirming a subagent had reached the current
build, because that field only exists in newer versions. Any field that changed recently works
as a build fingerprint. Issue #13 tracks making this a first-class check by having `kb_info`
report the server build identity directly, which would collapse all of the above into one call.
