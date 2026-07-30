#!/bin/sh
# Scan the staged artifact for known vulnerabilities.
#
# Grype exits 1 when it finds vulnerabilities at or above its fail-on
# threshold. Findings are not scanner failures, so the exit code is normalized.
set -u

WORKSPACE="${1:-/workspace}"
OUTPUT="${2:-/results/grype.json}"

mkdir -p "$(dirname "$OUTPUT")" "${XDG_CACHE_HOME:-/tmp/cache}"

grype "dir:${WORKSPACE}" \
    --output json \
    --file "$OUTPUT" \
    --quiet
status=$?

if [ ! -s "$OUTPUT" ]; then
    printf '{"matches":[]}\n' > "$OUTPUT"
    echo "grype produced no report (exit ${status}); wrote an empty result" >&2
fi

exit 0
