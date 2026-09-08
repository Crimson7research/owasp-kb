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

# Keep stdin open until the server has answered the last request, polling for
# the response rather than sleeping a fixed time.
#
# This was `{ request; sleep 3; } | docker run ...`, and the sleep was a race
# against container startup that it eventually lost. The sleep begins when the
# pipeline does, not when the container starts reading, so a slower host spends
# the whole budget on startup and EOF is already pending when the server reads
# the requests. It answers the three static ones and drops kb_info -- the only
# one that opens the index -- because the reader loop ends at EOF and cancels
# the work in flight with it.
#
# It failed exactly that way on a self-hosted runner and reproduces on demand:
# set the sleep to 0 against any built image and ids 1, 2 and 3 come back while
# id 4 does not.
WAIT_TICKS=${WAIT_TICKS:-600}   # 0.1s each, so 60s before giving up

OUT_FILE=$(mktemp)
RELEASE=$(mktemp -u)
CONTAINER="owasp-kb-smoke-$$"
# Named so the trap can remove it by name. The client runs in the background,
# so an unbounded wait would otherwise wedge CI on a container that never exits.
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -f "$OUT_FILE" "$RELEASE"' EXIT

# An ordinary pipe whose write end is held open by the loop, released by
# creating $RELEASE. Deliberately not a FIFO opened read-write from this shell:
# closing that fd destroys the buffer, so if the container had not yet attached
# its read end the requests were discarded and it then blocked forever on a
# pipe with no writer. That reintroduces the very race being fixed here, in a
# form that hangs instead of failing.
{ request; while [ ! -e "$RELEASE" ]; do sleep 0.1; done; } \
    | docker run -i --rm --name "$CONTAINER" --network none "$IMAGE" >"$OUT_FILE" 2>/dev/null &
DOCKER_PID=$!

for ((tick = 0; tick < WAIT_TICKS; tick++)); do
    if grep -q '"id":4' "$OUT_FILE" 2>/dev/null; then
        break
    fi
    # Stop waiting on a container that has already exited, rather than burning
    # the full timeout on output that is never going to arrive.
    if ! kill -0 "$DOCKER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

: >"$RELEASE"   # let the writer finish, which closes the server's stdin

# Bound the shutdown as well. The output has already been collected, so a
# container that does not exit promptly on EOF is a reason to stop waiting
# rather than to hang the job -- an unbounded `wait` here turns a slow exit
# into a stuck build with no output.
for ((tick = 0; tick < 100; tick++)); do
    if ! kill -0 "$DOCKER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
wait "$DOCKER_PID" 2>/dev/null || true

OUTPUT=$(cat "$OUT_FILE")

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
# kb_info's response on its own. The checks below assert what the *index*
# holds, and searching the whole exchange for them does not: tools/list carries
# every tool description, and those mention "ASVS 5.0.0" (owasp_related) and
# "lexically ranked" (cwe_search). Both checks therefore passed against an
# exchange containing no kb_info response at all, which is how a dropped
# kb_info reached the version check before anything reported it.
KB_INFO=$(printf '%s\n' "$OUTPUT" | grep '"id":4' || true)
if [ -z "$KB_INFO" ]; then
    echo "  FAIL: no kb_info response in the exchange" >&2
    echo "--- output ---" >&2
    printf '%s\n' "$OUTPUT" >&2
    exit 1
fi

check_kb_info() {
    if printf '%s' "$KB_INFO" | grep -q -- "$1"; then
        echo "  ok: $2"
    else
        echo "  FAIL: $2" >&2
        echo "--- kb_info response ---" >&2
        printf '%s\n' "$KB_INFO" >&2
        exit 1
    fi
}

check_kb_info '5.0.0' "ASVS 5.0.0 baked in"
check_kb_info "$EXPECTED_MODE" "retrieval mode is $EXPECTED_MODE"

# The licence texts, checked against the filesystem of the built image rather than
# against the Dockerfile that was supposed to put them there.
#
# The Dockerfile's COPY into /opt/owasp-kb/licenses/ has only ever been verified by
# grepping the Dockerfile text
# (tests/test_packaging.py::test_the_dockerfile_ships_every_license_text). That proves
# the instruction is written, not that the files arrive: a .dockerignore
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
  /opt/owasp-kb/licenses/LICENSE-OWASP-MASVS
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

# A check_kb_info comparing server_version to plugin.json's version stood here, as
# a lockstep assertion that the image and the plugin shipped beside it were one
# release. The plugin declares no version now -- it resolves from the commit -- so
# there is nothing left to compare against.
#
# The comparison was a proxy for "this image is the one published for this plugin",
# expressible only because a moving tag could not state it. The plugin pins the
# image by digest instead, which states it directly, and scripts/verify_pin.sh
# checks that the shipped digest resolves and carries the packs recorded for it in
# plugins/owasp-kb/pinned-packs.json. Two images can report the same version and
# hold different indexes; only a digest tells them apart. See ADRs 0014 and 0015.
#
# The kb_info response is still isolated above rather than searched for across the
# whole exchange, which is what caught a dropped kb_info reaching this point.

echo "  PASS"
