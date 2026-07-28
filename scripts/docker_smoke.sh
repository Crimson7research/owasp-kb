#!/usr/bin/env bash
# Verify an image serves MCP over stdio with no network access.
# Usage: scripts/docker_smoke.sh <image> <expected-retrieval-mode>
set -euo pipefail

IMAGE="${1:?usage: docker_smoke.sh <image> <expected-mode>}"
EXPECTED_MODE="${2:?usage: docker_smoke.sh <image> <expected-mode>}"

request() {
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
      '{"jsonrpc":"2.0","id":3,"method":"prompts/list"}' \
      '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kb_info","arguments":{}}}'
}

echo "== $IMAGE (--network none) =="
# The trailing sleep keeps stdin open: without it the pipe closes and the
# server can exit before answering the last request, so the tools/call
# response never arrives and the check fails spuriously.
OUTPUT=$({ request; sleep 3; } | docker run -i --rm --network none "$IMAGE" 2>/dev/null)

check() {
    if printf '%s' "$OUTPUT" | grep -q -- "$1"; then
        echo "  ok: $2"
    else
        echo "  FAIL: $2" >&2
        echo "--- output ---" >&2
        printf '%s\n' "$OUTPUT" >&2
        exit 1
    fi
}

for tool in kb_info owasp_search owasp_outline owasp_get owasp_checklist owasp_related owasp_roster; do
    check "\"$tool\"" "tool $tool advertised"
done
for prompt in asvs_chapter_review cheatsheet asvs_gap_report; do
    check "\"$prompt\"" "prompt $prompt advertised"
done
check '5.0.0' "ASVS 5.0.0 baked in"
check "$EXPECTED_MODE" "retrieval mode is $EXPECTED_MODE"

# Lockstep: the image and the plugin shipped beside it carry one version. A
# reconnect reports success whether or not the image is current, so drift is
# invisible at runtime unless the two are pinned together at build time. This
# turns a stale image into a build failure instead.
PLUGIN_VERSION=$(python3 -c \
  'import json,sys; print(json.load(open("plugins/owasp-kb/.claude-plugin/plugin.json"))["version"])')
check "\"server_version\": \"$PLUGIN_VERSION\"" \
  "server reports version $PLUGIN_VERSION, matching the plugin"

echo "  PASS"
