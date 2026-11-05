# Install

The repository and its images are both private, and they are **separate grants**:
SSH access to the repository does not authorise the registry. You need both.

## Prerequisites

```
docker login ghcr.io          # GitHub PAT, read:packages scope
```

**Your SSH key must work non-interactively.** Claude Code suppresses the prompts for
both the host fingerprint and the key passphrase, so anything that would have asked
a question instead surfaces as an unexplained clone failure:

- `github.com` in your `known_hosts` — `ssh-keyscan github.com >> ~/.ssh/known_hosts`
- a key `ssh` can use without asking. A passphraseless key at a default path is
  enough; a passphrase-protected key must be loaded in `ssh-agent`
  (`ssh-add ~/.ssh/id_ed25519`)

`owasp-kb doctor` checks both, by running `ssh -T git@github.com` under
`BatchMode` — the same non-interactive position the background refresh is in, so a
pass there predicts a working auto-update rather than merely approximating it.
The host CLI ships in the plugin's `scripts/`, off `PATH`.
`<scripts>` is the absolute directory the owasp-kb session-start note names.

## Why SSH and not HTTPS

Not a preference. The background marketplace refresh **disables git credential
helpers** for its `git pull`, so a private marketplace over HTTPS cannot
authenticate in the background at all, even with a helper configured. SSH remotes
are unaffected.

An HTTPS remote therefore never auto-updates: the pull fails, Claude Code falls
back to a full re-clone, and by default it deletes the existing clone *before*
re-cloning against a 120-second git timeout. Set this so a failed pull keeps the
working copy instead:

```
export CLAUDE_CODE_PLUGIN_KEEP_MARKETPLACE_ON_FAILURE=1
```

Worth putting in a shell profile for a team, not just a terminal.

## How new versions reach you

Neither manifest declares a `version`, so Claude Code resolves the plugin version
to the commit it fetched. Auto-update skips a plugin whose resolved version matches
what is installed — so because ours is the commit, **every merge to master is a new
version** and nothing has to be bumped for it to reach you. That is the reason the
`version` field was removed rather than automated; see ADR
[0014](decisions/0014-image-digest-pin.md).

A new image is a separate matter: it arrives when a release re-pins the digest,
which lands on master as its own commit and is delivered the same way.

## Claude Code

```
/plugin marketplace add git@github.com:Crimson7research/owasp-kb.git
/plugin install owasp-kb
```

`/plugin marketplace add` reads `.claude-plugin/marketplace.json`, which points at
`plugins/owasp-kb`. Installing registers the plugin's `.mcp.json`, its two
PreToolUse hooks, five agents and four skills.

To pull a change immediately rather than waiting for the background refresh, use
`/plugin marketplace update` then `/plugin update`. From the CLI the plugin needs
its qualified form — `claude plugin update owasp-kb@owasp-kb` — since bare
`owasp-kb` reports `Plugin not found`.

The server runs `ghcr.io/crimson7research/owasp-kb` **pinned by digest**. The
first start pulls it, roughly 700 MB for the `full` variant; later starts use the
local copy. Pull it deliberately rather than at the head of a session with:

```
python3 <scripts>/owasp-kb doctor --pull
```

A digest rather than a tag because a tag is shadowed by any local image of the
same name — `--pull=missing` is docker's default and `docker tag` is
unprivileged — while `--pull=always` would put registry reachability on the
critical path of every server start. See ADR
[0014](decisions/0014-image-digest-pin.md).

## Building from source

The contributor path, not the install path:

```
git clone git@github.com:Crimson7research/owasp-kb.git
cd owasp-kb
make build
```

This runs `fetch` (pinned sources into `data/`), `model` (the embedding model
into `models/`), both `index`/`index-full` builds, and both `docker build`
invocations, producing `owasp-kb:lite` and `owasp-kb:full` locally. Confirm with
`docker image inspect owasp-kb:full`, and point the plugin at one with
`OWASP_KB_IMAGE=owasp-kb:full`.

## Any MCP-capable agent

Point any MCP client at the pinned image. The reference is the
`${OWASP_KB_IMAGE:-...}` default in `plugins/owasp-kb/.mcp.json` — read it rather
than copying a literal, so a release cannot leave your config behind:

```
IMAGE=$(python3 -c 'import re,sys; print(re.search(r"\$\{OWASP_KB_IMAGE:-([^}]+)\}", open(sys.argv[1]).read()).group(1))' plugins/owasp-kb/.mcp.json)
claude mcp add owasp-kb -- docker run -i --rm --network none "$IMAGE"
```

or, editing an MCP config file by hand, the equivalent JSON entry:

```json
{
  "mcpServers": {
    "owasp-kb": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "none", "ghcr.io/crimson7research/owasp-kb@sha256:<digest>"]
    }
  }
}
```

For the smaller, lexical-only variant use the immutable content-named tag
`ghcr.io/crimson7research/owasp-kb:lite-asvs5.0.0-cs20260724-cwe4.20`. That is a
tag rather than a digest, which is a weaker guarantee — acceptable because it is an
explicit opt-in by someone overriding the default, and the tag already names every
pack in the index.
`--network none` is not optional — see the README's "Runs offline" section for
why.

**This is not quite `plugins/owasp-kb/.mcp.json`.** The plugin's entry runs the
same container through `sh -c`, and additionally creates and mounts the session
state directory read-only:

```
sh -c 'mkdir -p "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb" && exec docker run -i --rm --network none \
  -v "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb:/state:ro" ${OWASP_KB_IMAGE:-ghcr.io/crimson7research/owasp-kb@sha256:<digest>}'
```

`sh` rather than `docker` directly because the mount path needs shell
expansion, and `sh` is resolvable where a wrapper on the plugin's `bin/` was
not — the MCP subprocess does not inherit that `PATH`.

Without the mount the server still answers every knowledge question, so the
plain form above is the right one for a standalone client. What it cannot do is
read an assessment's accumulated findings: `owasp_roster` reads
`findings.jsonl` from `/state`, so with no mount an assessment must pass every
verdict inline on each call. ADR
[0013](decisions/0013-session-state-on-disk.md) explains what that costs.

## Codex

Codex installs the Claude Code plugin as it is. It reads
`.claude-plugin/marketplace.json` and `plugins/owasp-kb/.claude-plugin/plugin.json`:

```
codex plugin marketplace add Crimson7research/owasp-kb
codex plugin add owasp-kb@owasp-kb
```

That installs the skills, the MCP server entry from `.mcp.json` (pinned digest and
the `/state` mount) and the hooks. Update with:

```
codex plugin marketplace upgrade
```

Observed on `codex-cli 0.166.0`:

- **Hooks need a trust review.** Codex skips new or changed hooks until you
  review them in `/hooks`. Hooks live in `plugins/owasp-kb/hooks/hooks.json`,
  because Codex ignores hooks declared in `plugin.json`.
- **`codex exec` cannot call MCP tools by default.** Every call fails with
  `MCP tool call requires approval, but approval policy is never`. Interactive
  sessions prompt for approval instead.
- **The version column reads `local`.** The plugin declares no version, so the
  commit is the version (ADR [0014](decisions/0014-image-digest-pin.md)).
- **The two assessment skills do not complete.** `owasp-asvs-verify` and
  `owasp-asvs-gap-report` dispatch six agents. Codex copies `agents/*.md` into
  its plugin cache but does not register them. Issue #94 tracks the port.

## OpenCode

```
./install/opencode.sh
```

Copies the four skills to `${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skill`
and prints the equivalent `opencode.json` snippet:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "owasp-kb": {
      "type": "local",
      "command": ["docker", "run", "-i", "--rm", "--network", "none", "ghcr.io/crimson7research/owasp-kb@sha256:<digest>"],
      "enabled": true
    }
  }
}
```

Same digest resolution and the same `OWASP_KB_IMAGE` override apply.

## Session state on your machine

An assessment writes to
`${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb/sessions/<session-id>/`:

| File | Holds |
|---|---|
| `findings.jsonl` | One appended line per verdict, with file paths and code excerpts from the target |
| `inventory.md` | The scope survey of the target codebase |
| `report/NNN_*.md` | The report, section by section, merged by `owasp-kb report merge` |
| `concerns`, `excluded` | The lists that arm the inventory gate and the exclusion hook |
| `pending.txt` | The dispatch ledger |

**Nothing removes any of it.** It is engagement material and it persists until you
delete it, so on a machine used for several engagements it accumulates one set per
session, under opaque session ids.

```
python3 <scripts>/owasp-kb sessions list                       # what each session holds, and how big
python3 <scripts>/owasp-kb sessions purge <session-id> --yes    # remove one
python3 <scripts>/owasp-kb sessions purge --older-than 30 --yes # remove everything older than a month
```

Neither runs on a timer and neither deletes without `--yes`; both print exactly
what they would remove first. Purge is all-or-nothing across a batch, so a
mistyped id in a list deletes nothing rather than leaving you unsure which
sessions survived.

The listing does **not** record which codebase a session assessed — that identity
was deliberately removed from recorded state, so sessions are identified by date
and volume. ADR [0013](decisions/0013-session-state-on-disk.md) covers why the
state is on disk at all.

## Troubleshooting

**Run `python3 <scripts>/owasp-kb doctor` first.** It checks the chain end to
end and prints the fix for anything it finds. The `Check` column below is the
name doctor reports a symptom under.

| Symptom | Check | Cause |
|---|---|---|
| Anything at all, as a first step | — | `python3 <scripts>/owasp-kb doctor` |
| `docker: permission denied`, or docker missing | `docker` | Not on PATH, daemon down, or user not in the `docker` group |
| Tools absent right after installing | `plugin` | The plugin loaded from an unexpected directory; doctor prints which one it ran from |
| The configured image is a tag, not a digest | `pin` | `.mcp.json` was hand-edited, or `pin_image.py` never ran for this release |
| `unauthorized` / `denied` pulling the image | `image` | No `docker login ghcr.io`, or a PAT without the `read:packages` scope |
| A session start hangs for minutes | `image` | The pinned digest is not local yet; run `python3 <scripts>/owasp-kb doctor --pull` |
| `kb_info` reports `lexical` on the `full` image | `server` | Model or vectors missing from the image; the release smoke test should have caught it, so report it |
| Server starts then exits | `server` | Something wrote to stdout; logs must go to stderr |
| `no index at /opt/owasp-kb/...` | `server` | Image built without a baked index; run `make build` |
| `is still in WAL mode and cannot be served safely` | `server` | Index not finalized; rebuild via `make build-full`, which depends on `index-full` |
| The server's version disagrees with `pinned-packs.json` | `server` | The record and the image it names come from different releases: `pin_image.py` wrote one without the other, or the release wrote the version after building. With an `OWASP_KB_IMAGE` tag override instead of the shipped digest, the tag has moved — `docker pull` it |
| An exclusion or inventory gate never fires | `hooks` | A hook file the manifest names is absent. Doctor cannot see harness registration and says so |
| An assessment cannot write findings | `state` | The state directory is root-owned, usually from a bind mount the daemon created |
| Marketplace clone fails with no prompt | `ssh` | SSH does not authenticate to `github.com`. Doctor runs `ssh -T` and only then distinguishes the causes — an unknown host, an empty `ssh-agent`, or a key GitHub does not accept. Claude Code suppresses both the fingerprint and passphrase prompts, so none of these announce themselves |
| Repeated 120-second timeouts each session | `marketplace` | A failed pull re-clones; set `CLAUDE_CODE_PLUGIN_KEEP_MARKETPLACE_ON_FAILURE=1` |
| A plugin change is not taking effect | `plugin` | No longer expected: the version resolves from the commit, so every commit is a distinct cache key. If it happens, a `version` field has been reintroduced into a manifest — doctor reports that as a `plugin` failure |
