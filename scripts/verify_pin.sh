#!/usr/bin/env bash
# Verify the digest the plugin ships resolves, and that the image it names holds
# the packs sources.lock.yml declares.
#
# Separate from docker_smoke.sh on purpose: that script tests whichever image it is
# handed, and ci.yml hands it locally built tags. This asks a different question --
# does the *shipped reference* agree with the registry -- and it is the question the
# three deleted version-lockstep checks were weak proxies for. Two images can report
# the same server_version and hold different indexes; only a digest tells them apart.
# See ADR 0014.
set -euo pipefail

MCP_CONFIG=plugins/owasp-kb/.mcp.json

IMAGE="$(python3 -c '
import re, sys
text = open(sys.argv[1]).read()
match = re.search(r"\$\{OWASP_KB_IMAGE:-([^}]+)\}", text)
if not match:
    sys.exit("no ${OWASP_KB_IMAGE:-...} default in " + sys.argv[1])
print(match.group(1))
' "$MCP_CONFIG")"

echo "== shipped reference: $IMAGE =="

case "$IMAGE" in
    *"@sha256:"*) ;;
    *)
        echo "  FAIL: $MCP_CONFIG does not pin a digest ($IMAGE)" >&2
        echo "  A tag is shadowed by any local image of that name. Run" >&2
        echo "  scripts/pin_image.py --image <ref> --write with a published digest." >&2
        exit 1
        ;;
esac

docker pull --quiet "$IMAGE" >/dev/null
echo "  ok: the digest resolves and pulls"

EXPECTED="$(python3 -c '
import yaml
packs = yaml.safe_load(open("sources.lock.yml"))["packs"]
for name in sorted(packs):
    print(name + "=" + str(packs[name]["version"]))
')"

# Poll for the answer rather than sleeping at it, and read kb_info's response
# alone -- both for the reasons scripts/docker_smoke.sh documents at length: a
# fixed sleep races container startup, and the full exchange carries every tool
# description, several of which quote pack versions.
REQUESTS='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify-pin","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kb_info","arguments":{}}}'

OUT_FILE=$(mktemp)
trap 'rm -f "$OUT_FILE"' EXIT

printf '%s\n' "$REQUESTS" \
  | timeout 180 docker run -i --rm --network none "$IMAGE" >"$OUT_FILE" 2>/dev/null || true

KB_INFO=$(grep '"id":2' "$OUT_FILE" || true)
if [ -z "$KB_INFO" ]; then
    echo "  FAIL: no kb_info response from the pinned image" >&2
    echo "--- output ---" >&2
    cat "$OUT_FILE" >&2
    exit 1
fi

while IFS= read -r pair; do
    name="${pair%%=*}"
    version="${pair#*=}"
    if printf '%s' "$KB_INFO" | grep -q -- "$version"; then
        echo "  ok: pack $name reports $version"
    else
        echo "  FAIL: pack $name should report $version and does not" >&2
        echo "--- kb_info ---" >&2
        printf '%s\n' "$KB_INFO" >&2
        exit 1
    fi
done <<< "$EXPECTED"

echo "  PASS"
