#!/usr/bin/env bash
# Verify the digest the plugin ships resolves, and that the image it names holds
# the packs it was published with -- as recorded in plugins/owasp-kb/pinned-packs.json
# by scripts/pin_image.py at release time.
#
# It read sources.lock.yml directly until ADR 0015. That asserted the shipped image
# is current with whatever the branch declares, which no lock-bump commit can
# satisfy: the image holding those versions is not built until the release that
# follows the merge. Drift between the record and the lock is the normal state
# between a content refresh and the next release, so it is reported below and does
# not fail. What still fails is an image that does not hold what it claims to.
#
# Separate from docker_smoke.sh on purpose: that script tests whichever image it is
# handed, and ci.yml hands it locally built tags. This asks a different question --
# does the *shipped reference* agree with the registry -- and it is the question the
# three deleted version-lockstep checks were weak proxies for. Two images can report
# the same server_version and hold different indexes; only a digest tells them apart.
# See ADR 0014.
set -euo pipefail

MCP_CONFIG=plugins/owasp-kb/.mcp.json
PINNED_PACKS=plugins/owasp-kb/pinned-packs.json

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

# The record has to name this digest. A pin written without one -- by hand, or by a
# release that pushed .mcp.json and left the record behind -- would otherwise be
# checked against some earlier image's packs and pass.
EXPECTED="$(python3 -c '
import json, sys
record = json.load(open(sys.argv[1]))
if record["image"] != sys.argv[2]:
    sys.exit(
        "  FAIL: " + sys.argv[1] + " records " + record["image"] + "\n"
        "  but the plugin ships " + sys.argv[2] + ". Run\n"
        "  scripts/pin_image.py --image <ref> --write, which writes both."
    )
for name in sorted(record["packs"]):
    print(name + "=" + str(record["packs"][name]))
' "$PINNED_PACKS" "$IMAGE")"

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
        echo "  The shipped image does not hold what $PINNED_PACKS says it does." >&2
        echo "--- kb_info ---" >&2
        printf '%s\n' "$KB_INFO" >&2
        exit 1
    fi
done <<< "$EXPECTED"

# Reported, never failed. Between a content refresh landing and the release that
# ships it, the lock is ahead of the image by design, and there is no digest that
# could make this quiet. Silence would be worse than a notice: a release that never
# happened looks identical to one that did.
python3 -c '
import json, sys, yaml
recorded = json.load(open(sys.argv[1]))["packs"]
packs = yaml.safe_load(open("sources.lock.yml"))["packs"]
declared = {name: str(pack["version"]) for name, pack in packs.items()}
drift = sorted(n for n in set(recorded) | set(declared) if recorded.get(n) != declared.get(n))
if drift:
    print("  note: sources.lock.yml is ahead of the shipped image -- a release is pending")
    for name in drift:
        print("    " + name + ": shipped " + recorded.get(name, "-") + ", lock " + declared.get(name, "-"))
' "$PINNED_PACKS"

echo "  PASS"
