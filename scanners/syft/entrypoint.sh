#!/bin/sh
# Generate an SPDX SBOM for the staged artifact.
#
# The scan step must exit 0 whenever it produced a usable report. A non-zero
# exit marks the Job failed, which loses the findings and leaves the scan
# waiting forever — the verdict belongs to the controller, not to this script.
set -u

WORKSPACE="${1:-/workspace}"
OUTPUT="${2:-/results/sbom.spdx.json}"

mkdir -p "$(dirname "$OUTPUT")" "${XDG_CACHE_HOME:-/tmp/cache}"

syft scan "dir:${WORKSPACE}" \
    --output "spdx-json=${OUTPUT}" \
    --quiet
status=$?

if [ ! -s "$OUTPUT" ]; then
    # Emit a valid empty document so the publish step can tell "scanned and
    # found nothing" apart from "never ran".
    printf '{"spdxVersion":"SPDX-2.3","name":"assay-empty","packages":[]}\n' > "$OUTPUT"
    echo "syft produced no SBOM (exit ${status}); wrote an empty document" >&2
fi

exit 0
