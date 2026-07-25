#!/bin/sh
# Fail fast and actionably if the baked index is absent.
set -e

INDEX="${OWASP_KB_INDEX:-/opt/owasp-kb/owasp-kb.sqlite}"

if [ ! -f "$INDEX" ]; then
    echo "owasp-kb: no index at $INDEX" >&2
    echo "owasp-kb: this image was built without a baked index; rebuild with 'make build'" >&2
    exit 1
fi

exec python -m owasp_kb.server.app --index "$INDEX"
