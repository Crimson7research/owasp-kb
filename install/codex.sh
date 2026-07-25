#!/usr/bin/env bash
# Install the OWASP KB skills for Codex CLI and print the MCP config snippet.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_SRC="$REPO_ROOT/plugins/owasp-kb/skills"
SKILLS_DEST="${CODEX_HOME:-$HOME/.codex}/skills"
IMAGE="${OWASP_KB_IMAGE:-owasp-kb:full}"

[ -d "$SKILLS_SRC" ] || { echo "no skills at $SKILLS_SRC" >&2; exit 1; }

mkdir -p "$SKILLS_DEST"
for skill in "$SKILLS_SRC"/*/; do
    name="$(basename "$skill")"
    rm -rf "${SKILLS_DEST:?}/$name"
    cp -r "$skill" "$SKILLS_DEST/$name"
    echo "installed skill: $name"
done

cat <<EOF

Skills installed to $SKILLS_DEST

Add the MCP server to ${CODEX_HOME:-$HOME/.codex}/config.toml:

  [mcp_servers.owasp-kb]
  command = "docker"
  args = ["run", "-i", "--rm", "--network", "none", "$IMAGE"]

Then confirm the image exists:

  docker image inspect $IMAGE >/dev/null && echo ok
EOF
