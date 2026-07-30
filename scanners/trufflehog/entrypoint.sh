#!/bin/sh
# Scan the staged artifact for embedded credentials.
#
# TruffleHog exits non-zero when it finds secrets. That is a finding, not a
# scanner failure, so it is normalized to 0 — the controller decides the
# verdict, and a failed Job would discard the results.
set -u

WORKSPACE="${1:-/workspace}"
OUTPUT="${2:-/results/trufflehog.json}"

mkdir -p "$(dirname "$OUTPUT")" "${XDG_CACHE_HOME:-/tmp/cache}"

# --no-update keeps the scan deterministic and works in an air-gapped cluster.
# --no-verification stops the scanner from calling out to third-party APIs to
# confirm a credential, which would leak the secret it just found.
trufflehog filesystem "$WORKSPACE" \
    --json \
    --no-update \
    --no-verification \
    > "$OUTPUT" 2>/tmp/trufflehog.err
status=$?

if [ ! -f "$OUTPUT" ]; then
    : > "$OUTPUT"
fi

if [ "$status" -ne 0 ] && [ ! -s "$OUTPUT" ]; then
    echo "trufflehog exited ${status} with no output:" >&2
    tail -20 /tmp/trufflehog.err >&2
fi

exit 0
