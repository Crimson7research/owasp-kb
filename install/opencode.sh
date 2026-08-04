#!/usr/bin/env bash
# Install the OWASP KB skills for OpenCode and print the MCP config snippet.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_SRC="$REPO_ROOT/plugins/owasp-kb/skills"
SKILLS_DEST="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skill"

# The plugin's .mcp.json is the single source of truth for which image ships.
# Repeating the reference here would give a release three literals to keep in step
# and nothing to catch one going stale.
DEFAULT_IMAGE="$(python3 -c '
import re, sys
text = open(sys.argv[1]).read()
match = re.search(r"\$\{OWASP_KB_IMAGE:-([^}]+)\}", text)
if not match:
    sys.exit("no ${OWASP_KB_IMAGE:-...} default in " + sys.argv[1])
print(match.group(1))
' "$REPO_ROOT/plugins/owasp-kb/.mcp.json")"
IMAGE="${OWASP_KB_IMAGE:-$DEFAULT_IMAGE}"

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

Add the MCP server to your OpenCode config (e.g. opencode.json):

  {
    "\$schema": "https://opencode.ai/config.json",
    "mcp": {
      "owasp-kb": {
        "type": "local",
        "command": ["docker", "run", "-i", "--rm", "--network", "none", "$IMAGE"],
        "enabled": true
      }
    }
  }

Then confirm the image exists:

  docker image inspect $IMAGE >/dev/null && echo ok
EOF
