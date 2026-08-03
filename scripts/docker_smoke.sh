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

# All ten, not the original seven. A presence check is cheap and this is the only
# place anything runs against a built image: an image whose cwe_get failed to
# register would otherwise ship, and the plugin's agents now instruct callers to
# use it.
for tool in kb_info owasp_search owasp_outline owasp_get owasp_checklist owasp_related owasp_roster cwe_get cwe_search cwe_related; do
    check "\"$tool\"" "tool $tool advertised"
done
for prompt in asvs_chapter_review cheatsheet asvs_gap_report; do
    check "\"$prompt\"" "prompt $prompt advertised"
done
check '5.0.0' "ASVS 5.0.0 baked in"
check "$EXPECTED_MODE" "retrieval mode is $EXPECTED_MODE"

# The licence texts, checked against the filesystem of the built image rather than
# against the Dockerfile that was supposed to put them there.
#
# The Dockerfile's COPY into /opt/owasp-kb/licenses/ has only ever been verified
# by grepping the Dockerfile text
# (tests/test_packaging.py::test_the_dockerfile_ships_every_license_text). That
# proves the instruction is written, not that the files arrive: a .dockerignore
# entry, a build context change or a later stage that does not inherit the layer
# would all leave the COPY in place and the files absent. docs/licensing.md asks a
# redistributor to carry each pack's licence text with the artifact, and CWE's
# terms of use require it, so an image missing them is a licence problem and not a
# cosmetic one.
#
# Separate `docker run` from the one above: that container is consumed by the MCP
# stdio exchange, and this needs a plain command in the same image.
echo "  -- licence texts in the image --"
LICENSES=(
  /opt/owasp-kb/licenses/LICENSE
  /opt/owasp-kb/licenses/LICENSE-OWASP-ASVS
  /opt/owasp-kb/licenses/LICENSE-OWASP-CHEATSHEET
  /opt/owasp-kb/licenses/LICENSE-CWE
  /opt/owasp-kb/licenses/NOTICE
)
# -s, not -f: a zero-byte licence text satisfies the COPY and is not a licence.
LICENSE_LS=$(docker run --rm --network none --entrypoint sh "$IMAGE" -c \
  'for f in "$@"; do if [ -s "$f" ]; then echo "present $f"; else echo "absent $f"; fi; done' \
  sh "${LICENSES[@]}" 2>&1 || true)
for path in "${LICENSES[@]}"; do
    if printf '%s\n' "$LICENSE_LS" | grep -qxF -- "present $path"; then
        echo "  ok: $path present and non-empty"
    else
        echo "  FAIL: $path missing or empty in the image" >&2
        echo "--- /opt/owasp-kb/licenses/ ---" >&2
        printf '%s\n' "$LICENSE_LS" >&2
        exit 1
    fi
done

# Lockstep: the image and the plugin shipped beside it carry one version. A
# reconnect reports success whether or not the image is current, so drift is
# invisible at runtime unless the two are pinned together at build time. This
# turns a stale image into a build failure instead.
PLUGIN_VERSION=$(python3 -c \
  'import json,sys; print(json.load(open("plugins/owasp-kb/.claude-plugin/plugin.json"))["version"])')
# kb_info's body arrives as escaped JSON inside content[0].text, so the quotes
# are backslashed. Match loosely but bound it to before the next comma, or a
# pack version elsewhere in the payload could satisfy it.
check "server_version[^,]*$PLUGIN_VERSION" \
  "server reports version $PLUGIN_VERSION, matching the plugin"

echo "  PASS"
