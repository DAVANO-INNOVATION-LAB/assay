#!/bin/sh
# Scan the staged artifact for malware.
#
# clamscan exit codes: 0 = clean, 1 = infected, 2 = error. Only 2 is a real
# scanner failure, and even then the partial output is kept. Findings are
# reported through the output file, never through the exit code, so the
# controller stays the only thing that decides a verdict.
set -u

WORKSPACE="${1:-/workspace}"
OUTPUT="${2:-/results/clamav.txt}"
DBDIR="${CLAMAV_DB_DIR:-/opt/clamav-db}"

mkdir -p "$(dirname "$OUTPUT")"

# Refuse to run signature-less: an empty database would report every artifact
# as clean, which is far worse than an honest scanner error.
if [ ! -d "$DBDIR" ] || [ -z "$(ls -A "$DBDIR" 2>/dev/null)" ]; then
    echo "clamav signature database is empty at ${DBDIR}; refusing to report a clean scan" >&2
    exit 2
fi

clamscan --recursive --infected --no-summary \
    --database="$DBDIR" \
    --max-filesize=4000M \
    --max-scansize=4000M \
    --max-recursion=32 \
    --stdout \
    "$WORKSPACE" > "$OUTPUT" 2>/tmp/clamav.err
status=$?

case "$status" in
    0) ;;                                    # clean
    1) echo "clamav found infected files" >&2 ;;
    *)
        echo "clamav errored (exit ${status}):" >&2
        tail -20 /tmp/clamav.err >&2
        # A scanner error must not look like a clean scan. Exiting non-zero
        # marks the Job failed, and the controller records the scanner as
        # Error rather than Passed.
        exit "$status"
        ;;
esac

exit 0
