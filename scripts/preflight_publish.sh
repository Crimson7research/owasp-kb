#!/usr/bin/env bash
# Check every surface that survives a history rewrite for identifiers belonging to
# an assessed target. See docs/publishing.md.
#
# The pattern list is gitignored on purpose: a committed list of the names to
# scrub is itself a leak.
set -euo pipefail

PATTERNS="${1:-.publish-scrub}"

if [[ ! -f "$PATTERNS" ]]; then
    cat >&2 <<EOF
No pattern file at '$PATTERNS'.

    cp .publish-scrub.example .publish-scrub

Then add one identifier per line — repository names, symbol names, file paths,
hostnames — for every target this project has been run against. Lines starting
with '#' and blank lines are ignored.
EOF
    exit 2
fi

# Surfaces that a fresh repository carries forward. Git history is deliberately
# not checked; docs/superpowers/ needs no exclusion because it is gitignored and
# so never enters a tracked surface at all.
SURFACES=(
    plugins/
    src/
    docker/
    scripts/
    .claude/
    README.md
    NOTICE
    docs/
)

mapfile -t RAW < <(grep -vE '^\s*(#|$)' "$PATTERNS")
if [[ ${#RAW[@]} -eq 0 ]]; then
    echo "FAIL: '$PATTERNS' has no patterns. An empty list passes everything." >&2
    exit 2
fi

echo "== preflight: ${#RAW[@]} pattern(s) over ${#SURFACES[@]} surface(s) =="

FOUND=0
for pat in "${RAW[@]}"; do
    # -I skips binaries.
    if hits=$(git grep -nIF -- "$pat" "${SURFACES[@]}" 2>/dev/null); then
        FOUND=1
        echo "  HIT: $pat"
        printf '       %s\n' "$hits"
    fi
done

if [[ $FOUND -eq 1 ]]; then
    cat >&2 <<'EOF'

FAIL: an assessed target's identifier appears in a surface that survives a
history rewrite. These ship as product, so a fresh repository carries them.

Rewrite the example to describe the shape it illustrates rather than naming
real code — that is usually all an example needed in the first place.
EOF
    exit 1
fi

echo "  ok: no target identifiers in any surviving surface"
echo "  PASS"
echo
echo "Mechanical check only. docs/publishing.md lists what still needs judgement:"
echo "  license texts in the image, per-pack terms, name/description coherence,"
echo "  version lockstep, and whether reasoning that cited a target was rewritten."
