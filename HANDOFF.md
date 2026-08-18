# Assay — session handoff

Renamed from **Zeus** on 2026-08-11 (Zeus = banking-trojan family). Directory is
still `~/m-dev/zeus`; module is `github.com/DAVANO-INNOVATION-LAB/assay`; API group is
`security.davano.io` (org-tied on purpose, so a product rename never breaks CRs).
Org is **Davano**.

## State (updated 2026-08-18)
- **GitHub repo moved** JUMP1ST/zeus-model-scanner → **DAVANO-INNOVATION-LAB/assay**
  (transfer, history + redirects preserved). Module path rewritten repo-wide;
  full suite green under it; local `origin` already points at the new URL.
- **Standalone CLI shipped**: `cmd/assay`, `assay inspect <path>` runs the same
  inspector + policy spine cluster-free. CI exit codes (0 Approved / 2 Review /
  3 Quarantined / 1 error), `--json`, `make cli` / `cli-release`.
- **ModelSource interface** (`internal/modelsource`): `Source` =
  List/Resolve/WriteBack. Two impls — OpenShift Model Registry adapter and a new
  **MLflow** source (artifact-proxy staging; verdict written back as
  `assay.verdict` / `assay.risk_score` tags). httptest unit tests + a Docker-gated
  **live test** (`make test-mlflow`, `-tags mlflow_live`) that registers a
  malicious pickle in a real MLflow server and asserts Quarantined + tag written
  back. Verified passing (Quarantined, risk 60).
- Prior real fix still stands: pickle **protocol 4/5 `STACK_GLOBAL`** detection,
  6-protocol regression test in `internal/inspector/pickleproto_test.go`.
- Ran end-to-end on a **kind** cluster; demo UI at `ui/index.html` served via
  `kubectl proxy --www` (POSTs `ArtifactScan`s, reads back reports live).

## Scope (deliberately narrow)
Supply-chain security for the model **artifact**: malware, unsafe
deserialization, CVEs, secrets, provenance. **Not** behavioural AI eval
(prompt injection / jailbreak / backdoor / adversarial robustness) — open
research, explicitly out of scope in the README, not a roadmap.

## Known liabilities (do not paper over)
- Never run against a real OpenShift AI Model Registry.
- S3 / ODF / ModelCar resolvers compile but are **untested against real storage**.
- **PVC resolver has no mount wired in `internal/controller/jobs.go`.**
- Admission webhook off on kind (no cert-manager).
- Demo UI writes to the cluster via `kubectl proxy` (full kubeconfig — demo only).
- Permissive by design: `--require-report=false`, webhook `failurePolicy: Ignore`.

## Next steps
Done since 2026-08-11: repo moved to the Davano org (~~GitHub rename~~), CLI
shipped (was step 2), MLflow via generalized `ModelSource` (was step 3).
Remaining:
1. **quay `davano/` namespace** — image repos still under old naming; rename or
   recreate `quay.io/davano/assay-operator` + `scanner-*` (needs Docker/quay creds).
   This is the only unfinished piece of the org move; needs the user.
2. **Wire the MLflow `Source` into the in-cluster controller.** Today it's
   proven via the CLI/test path (`internal/modelsource`); make it a connector
   trigger alongside `ModelRegistryConnector` so a cluster polls MLflow directly.
3. Runtime scanning = KServe `InferenceService` admission gate + init-container
   scan-gate. Registry scan and runtime scan are the **same pipeline, different
   triggers** — one spine, two triggers.
4. Langfuse = verdict×trace **correlation**, not model scanning — keep separate.

## Resume the live demo (after restarting Docker Desktop)
```
kind create cluster --name assay-demo        # if gone
make install                                  # CRDs under security.davano.io
# load images into kind: quay.io/davano/assay-operator:0.1.0 + scanner-*:0.1.0
make -C scanners ...                          # or docker tag + kind load
# run operator (out-of-cluster is fine): go run ./cmd/manager --enable-webhook=false ...
# UI: kubectl proxy --port=8903 --www=./ui --www-prefix=/ui/
```
