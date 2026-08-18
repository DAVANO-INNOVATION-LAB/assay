#!/usr/bin/env bash
# Regenerates internal/results/testdata/real_*.
#
# Those fixtures are verbatim scanner output, and the parser tests assert
# against them. Hand-written fixtures only prove the parsers handle the format
# we assumed; these prove they handle the format the tools actually emit.
#
# Run this after bumping a scanner version, then re-run `make test` — a parser
# that silently stopped matching will fail here rather than in production.
set -euo pipefail

REGISTRY="${1:-quay.io/davano}"
TAG="${2:-0.1.0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTDATA="$REPO_ROOT/internal/results/testdata"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/model"
RESULTS="$WORK/results"
mkdir -p "$FIXTURE" "$RESULTS" "$TESTDATA"

printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "$FIXTURE/suspicious.dat"

cat > "$FIXTURE/requirements.txt" <<'EOF'
torch==1.13.0
transformers==4.30.0
pillow==9.0.0
requests==2.19.1
pyyaml==5.3
EOF

# Synthesized at run time, never committed. See scanners/smoke-test.sh for why.
rand() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }

cat > "$FIXTURE/train_config.py" <<EOF
AWS_ACCESS_KEY_ID = "AKIA$(rand 'A-Z0-9' 16)"
AWS_SECRET_ACCESS_KEY = "$(rand 'A-Za-z0-9' 40)"
GITHUB_TOKEN = "ghp_$(rand 'A-Za-z0-9' 36)"
EOF

run_scanner() {
    docker run --rm \
        --network none --read-only --user 65532:65532 --cap-drop ALL \
        --tmpfs /tmp:rw,size=2g \
        -v "$FIXTURE:/workspace:ro" \
        -v "$RESULTS:/results" \
        "${REGISTRY}/scanner-${1}:${TAG}" \
        /workspace "/results/${2}"
}

echo "==> capturing scanner output"
run_scanner clamav     clamav.txt
run_scanner trivy      trivy.json
run_scanner trufflehog trufflehog.json
run_scanner syft       sbom.spdx.json

cp "$RESULTS/clamav.txt"     "$TESTDATA/real_clamav.txt"
cp "$RESULTS/trivy.json"     "$TESTDATA/real_trivy.json"
cp "$RESULTS/sbom.spdx.json" "$TESTDATA/real_syft_spdx.json"

# TruffleHog echoes the credential it found in Raw/RawV2. Trivy already masks
# its matches; TruffleHog does not, so strip those fields before the fixture
# lands in the repository. The parser reads DetectorName, Verified, and
# SourceMetadata, so nothing under test is lost.
python3 - "$RESULTS/trufflehog.json" "$TESTDATA/real_trufflehog.json" <<'PY'
import json, sys

src, dst = sys.argv[1], sys.argv[2]
out = []
for line in open(src):
    stripped = line.strip()
    if not stripped.startswith("{"):
        out.append(line.rstrip("\n"))
        continue
    record = json.loads(stripped)
    for field in ("Raw", "RawV2", "Redacted", "ExtraData"):
        if field in record:
            record[field] = "REDACTED-BY-ASSAY-FIXTURE-CAPTURE"
    out.append(json.dumps(record))

open(dst, "w").write("\n".join(out) + "\n")
PY

echo "==> updated fixtures in $TESTDATA"
ls -la "$TESTDATA"
echo
echo "Now run: make test"
