# Install

The repository is currently **private**, so every path below starts from a
local build rather than a GHCR pull: `release.yml` does publish images to
`ghcr.io/<owner>/owasp-kb`, but reaching them still requires access to this
private repo (and, for now, to a private registry namespace), so `make build`
against the cloned repo is the primary, always-available path.

```
git clone <this repo>
cd owasp-kb
make build
```

This runs `fetch` (pinned sources into `data/`), `model` (the embedding model
into `models/`), both `index`/`index-full` builds, and both
`docker build` invocations, producing `owasp-kb:lite` and `owasp-kb:full`
locally. Confirm with `docker image inspect owasp-kb:full`.

## Claude Code

From the cloned repo:

```
/plugin marketplace add /path/to/owasp-kb
/plugin install owasp-kb
```

`/plugin marketplace add` reads `.claude-plugin/marketplace.json`, which
points at `plugins/owasp-kb`. Installing the plugin registers its
`.mcp.json` (which runs `docker run -i --rm --network none owasp-kb:full`)
and copies its four skills into Claude Code's skill search path. No further
configuration is needed as long as `owasp-kb:full` exists locally (see
`make build` above).

## Any MCP-capable agent

Point any MCP client directly at the built image:

```
claude mcp add owasp-kb -- docker run -i --rm --network none owasp-kb:full
```

or, editing an MCP config file by hand, the equivalent JSON entry:

```json
{
  "mcpServers": {
    "owasp-kb": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "none", "owasp-kb:full"]
    }
  }
}
```

Swap `owasp-kb:full` for `owasp-kb:lite` for the smaller, lexical-only image.
`--network none` is not optional — see the README's "Runs offline" section for
why.

**This is not quite `plugins/owasp-kb/.mcp.json`.** The plugin's entry runs the
same container through `sh -c`, and additionally creates and mounts the session
state directory read-only:

```
sh -c 'mkdir -p "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb" && exec docker run -i --rm --network none \
  -v "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/owasp-kb:/state:ro" ${OWASP_KB_IMAGE:-owasp-kb:full}'
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

```
./install/codex.sh
```

Copies the four skills to `${CODEX_HOME:-$HOME/.codex}/skills` and prints the
`config.toml` snippet to add:

```toml
[mcp_servers.owasp-kb]
command = "docker"
args = ["run", "-i", "--rm", "--network", "none", "owasp-kb:full"]
```

Set `OWASP_KB_IMAGE` before running the script to install pointing at a
different tag (e.g. an immutable `owasp-kb:full-asvs5.0.0-cs20260724-cwe4.20`).

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
      "command": ["docker", "run", "-i", "--rm", "--network", "none", "owasp-kb:full"],
      "enabled": true
    }
  }
}
```

Same `OWASP_KB_IMAGE` override applies.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `no index at /opt/owasp-kb/...` | Image built without a baked index; run `make build` |
| `is still in WAL mode and cannot be served safely` | Index not finalized; rebuild via `make build-full`, which depends on `index-full` |
| `kb_info` reports `lexical` on the `full` image | Model or vectors missing; check `COPY models/` |
| Server starts then exits | Something wrote to stdout; logs must go to stderr |
| Tools absent in Claude Code | Plugin enabled but not reloaded; `/reload-plugins` |
| A plugin change is not taking effect | The cache is keyed on the version. If the version did not change, `/plugin` says "already at the latest version", `/mcp` reports a successful reconnect and `/reload-plugins` reloads the old files — all three true about the wrong copy. Bump the version, or uninstall and reinstall to recover. See [build.md](build.md#the-plugin-version-is-the-delivery-mechanism) |
| `docker: permission denied` | User not in the `docker` group |
