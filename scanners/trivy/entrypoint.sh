#!/bin/sh
# Scan the staged artifact for known vulnerabilities and embedded secrets.
#
# Trivy exits non-zero when findings meet its severity threshold. Findings are
# the expected outcome of a scan, not a failure, so the exit code is
# normalized — the controller owns the verdict.
set -u

WORKSPACE="${1:-/workspace}"
OUTPUT="${2:-/results/trivy.json}"

mkdir -p "$(dirname "$OUTPUT")" /tmp/cache

# The baked database directory is read-only. Trivy's scan cache already
# defaults to memory, so nothing tries to write next to the database.
trivy filesystem "$WORKSPACE" \
    --format json \
    --output "$OUTPUT" \
    --scanners vuln,secret \
    --quiet
status=$?

if [ ! -s "$OUTPUT" ]; then
    printf '{"Results":[]}\n' > "$OUTPUT"
    echo "trivy produced no report (exit ${status}); wrote an empty result" >&2
fi

exit 0
