#!/usr/bin/env bash
# Runs every scanner image against a planted artifact under the same
# constraints the operator applies in-cluster: no network, read-only root
# filesystem, non-root user, all capabilities dropped.
#
# This is what catches the failures unit tests cannot see — a tool that needs
# a writable path, or one that silently reports clean because its database
# never made it into the image.
set -euo pipefail

REGISTRY="${1:-ghcr.io/davano-innovation-lab}"
TAG="${2:-0.1.0}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/model"
RESULTS="$WORK/results"
mkdir -p "$FIXTURE" "$RESULTS"

# The scanners run as uid 65532, and this directory is created by whoever ran
# the script. On Linux that mismatch means every scanner fails to write its
# report; on macOS the Docker Desktop file-sharing layer papers over it, which
# is why this passes on a laptop and fails in CI.
#
# Only the test harness needs this. In a real scan the results directory is an
# emptyDir that Kubernetes provisions with the right ownership.
chmod 0777 "$RESULTS"

# EICAR: the standard antivirus test string. Not malware; every engine is
# required to detect it, which is what makes it a usable signal here.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "$FIXTURE/suspicious.dat"

# Dependency pins with known CVEs.
cat > "$FIXTURE/requirements.txt" <<'EOF'
torch==1.13.0
transformers==4.30.0
pillow==9.0.0
requests==2.19.1
pyyaml==5.3
EOF

# Credentials are synthesized at run time rather than committed as literals.
# They have to look live enough for the detectors to fire, which is exactly
# why they must not exist in the repository: committed test credentials trip
# push protection and every downstream secret scanner, and they teach
# reviewers to wave through exactly the pattern that matters.
#
# AWS's own documented example key is deliberately avoided too — scanners
# allowlist it, so it would silently prove nothing.
rand() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }

cat > "$FIXTURE/train_config.py" <<EOF
AWS_ACCESS_KEY_ID = "AKIA$(rand 'A-Z0-9' 16)"
AWS_SECRET_ACCESS_KEY = "$(rand 'A-Za-z0-9' 40)"
GITHUB_TOKEN = "ghp_$(rand 'A-Za-z0-9' 36)"
EOF

run_scanner() {
    local name="$1" output="$2"
    echo "==> ${name}"
    docker run --rm \
        --network none \
        --read-only \
        --user 65532:65532 \
        --cap-drop ALL \
        --tmpfs /tmp:rw,size=2g \
        -v "$FIXTURE:/workspace:ro" \
        -v "$RESULTS:/results" \
        "${REGISTRY}/scanner-${name}:${TAG}" \
        /workspace "/results/${output}"
}

fail=0
expect_match() {
    local file="$1" pattern="$2" description="$3"
    # Case-insensitive: scanners are inconsistent about signature casing
    # (ClamAV reports "Eicar-Test-Signature", not "EICAR").
    if grep -qi "$pattern" "$RESULTS/$file" 2>/dev/null; then
        echo "    ok: ${description}"
    else
        echo "    FAIL: ${description}" >&2
        fail=1
    fi
}

run_scanner clamav clamav.txt
expect_match clamav.txt "EICAR" "clamav detected the EICAR test file"

run_scanner trivy trivy.json
expect_match trivy.json "CVE-" "trivy reported CVEs from the baked database"
expect_match trivy.json "aws-access-key-id" "trivy detected the planted AWS key"

run_scanner trufflehog trufflehog.json
expect_match trufflehog.json '"DetectorName":"AWS"' "trufflehog detected the AWS credential"

run_scanner syft sbom.spdx.json
expect_match sbom.spdx.json "spdxVersion" "syft produced an SPDX document"
expect_match sbom.spdx.json "pillow" "syft catalogued the pinned dependencies"

if [ "$fail" -ne 0 ]; then
    echo "smoke test FAILED" >&2
    exit 1
fi
echo "all scanners passed"
