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

## Fixed 2026-08-18 (four bugs that each made the gate a no-op)
Found by auditing for scaffold-vs-real; all four failed **open** and silently,
so nothing looked broken. Each has a regression test that fails on the old code.
1. **Gate never found its reports.** Reports are written in the pipeline's
   namespace; the gate looked in the *workload's*. Always NotFound, which with
   `--require-report=false` reads as "unscanned, admit" — every workload the
   gate existed to stop went through. Now searches workload ns then
   `--report-namespace` (from `POD_NAMESPACE`); same fix for the policy lookup.
2. **PVC mount clobbered by the pull secret.** With `--pull-secret` set (normal
   prod config) the fetch mount list was rebuilt from the base and lost the
   claim. Pod declared a volume no container mounted — accepted silently.
3. **Scan container held a cluster token.** Automount was never disabled, so the
   kubelet injected the SA token into the step that parses hostile bytes; that
   token can create ArtifactScanReports, i.e. forge a clean verdict. Now
   projected into `publish` only. The old test couldn't see kubelet injection.
4. **`readyz` was `healthz.Ping`** → pod Ready before the webhook served TLS →
   open gate on every rollout. Now `StartedChecker()`.
Also: digest-pinning chain never connected (gate's replay check compared an
always-empty field), stuck scans requeued forever, reports had no ownerRefs.

## Known liabilities (do not paper over)
- Never run against a real OpenShift AI Model Registry. **`normalizeArtifactURI`
  treats `storageKey` as an S3 bucket; in OpenShift AI that names the
  data-connection Secret. Validate before trusting any `s3://` scan it builds.**
- OCI / ModelCar resolvers compile but are **untested against a real registry**.
  S3/ODF is now live-tested against MinIO (`make test-s3`); PVC is wired+covered.
- Admission webhook off on kind (no cert-manager). **There is still no cert path
  for non-OpenShift clusters** — the Secret is populated by the OpenShift
  service-CA operator, and on plain k8s the pod hangs on the missing volume.
- Demo UI writes to the cluster via `kubectl proxy` (full kubeconfig — demo only).
- Permissive by design: `--require-report=false`, webhook `failurePolicy: Ignore`.
  Both fail open, which is why the metrics below exist.
- `security.davano.io/skip-validation` is a self-service bypass any workload
  author can set. Counted now (`outcome="allowed_skip_annotation"`), not blocked.
- `assay-scanner` SA/Role exist only in `assay-system`, but Jobs are created in
  `scan.Namespace` — **a scan outside assay-system references a missing SA and
  stays Pending.** Not yet fixed.
- Storage/registry credentials are cluster-global operator flags, not per-CR
  Secret refs. No IRSA, no `AWS_SESSION_TOKEN`, no CA bundle for ODF.
- `TrustedPublisher` and `PromotionRequest` CRDs ship with no controller and no
  RBAC. `ApprovedEnvironments` is read by the gate and written by nothing.
- No NetworkPolicy on scan pods; the air-gap claim is documentation, not
  enforcement. `Definition.NeedsNetwork` is declared and unread.
- No Kustomize/Helm/OLM packaging — loose YAML and `make deploy` only.

## Also added 2026-08-18
- **CI from nothing**: build/vet/lint/race, `go mod tidy` + generated-code drift
  gates, a CLI exit-code end-to-end job, the live MLflow scan, and an image
  build. Plus `.golangci.yml` and a release workflow (cross-compiled CLI +
  checksums + multi-arch image to GHCR).
- **Metrics from nothing** (`internal/metrics`): `assay_admission_decisions_total`
  separates approved / unscanned / annotation-skipped — three facts that produce
  identical admission responses. Scan verdicts+durations, per-scanner results,
  source sync failures. `config/monitoring/metrics.yaml` ships Service,
  ServiceMonitor and alerts.
- `--scan-deadline-minutes` (stuck scans), report ownerRefs (etcd growth + stale
  report poisoning), uncached Secret reads (was caching every Secret in the
  cluster on a 512Mi limit; RBAC narrowed to `get`), connector reports Degraded
  on partial sync failure instead of Ready.
- Deployment: PDB, anti-affinity, maxUnavailable 0, preStop drain,
  system-cluster-critical, startupProbe. `config/namespace.yaml` split out so
  `make deploy` works on a fresh cluster.
- Unbuilt catalog entries (yara/license/ai-safety) are rejected instead of
  producing an ImagePullBackOff that hangs a scan.

## Next steps
1. **quay `davano/` namespace** — needs Docker/quay creds; user must do it. (CI
   now also publishes to GHCR under the org, which may make quay moot.)
2. **Cert path for non-OpenShift** — cert-manager `Certificate` + `caBundle`
   injection, or an in-process self-signed generator. Today plain k8s can't run
   the webhook at all.
3. **Cross-namespace scanning** — propagate the `assay-scanner` SA/Role (and the
   pull/storage Secrets) per namespace, or enforce single-namespace explicitly.
4. **Wire the MLflow `Source` into the controller** as a connector trigger
   alongside `ModelRegistryConnector`; today it's the CLI/test path only.
5. **Validate `normalizeArtifactURI` against a real Model Registry** before
   trusting any `s3://` URI it synthesizes (see liabilities).
6. Runtime scanning = KServe `InferenceService` admission gate + init-container
   scan-gate. Registry scan and runtime scan are the **same pipeline, different
   triggers** — one spine, two triggers.
7. Langfuse = verdict×trace **correlation**, not model scanning — keep separate.

## Resume the live demo (after restarting Docker Desktop)
```
kind create cluster --name assay-demo        # if gone
make install                                  # CRDs under security.davano.io
# load images into kind: quay.io/davano/assay-operator:0.1.0 + scanner-*:0.1.0
make -C scanners ...                          # or docker tag + kind load
# run operator (out-of-cluster is fine): go run ./cmd/manager --enable-webhook=false ...
# UI: kubectl proxy --port=8903 --www=./ui --www-prefix=/ui/
```
