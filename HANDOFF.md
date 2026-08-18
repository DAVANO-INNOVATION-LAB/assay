# Assay — session handoff

Renamed from **Zeus** on 2026-08-11 (Zeus = banking-trojan family). Directory is
still `~/m-dev/zeus`; module is `github.com/JUMP1ST/assay`; API group is
`security.davano.io` (org-tied on purpose, so a product rename never breaks CRs).
Org is **Davano**.

## State
- Rename is complete and **verified green**: `go build ./...`, `go vet`, and the
  full test suite all pass. Uncommitted at time of writing.
- Real fix this session: pickle **protocol 4/5 `STACK_GLOBAL`** evaded the
  Critical dangerous-import check (a plain `pickle.dumps()` of `os.system`, since
  Python's default is protocol 5, degraded to a generic warning). Fixed, with a
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

## Next steps (decided 2026-08-11)
1. Commit the rename; then rename the GitHub repo + quay `davano/` namespace.
2. Ship the standalone inspector CLI (`assay inspect <path>`) publicly first —
   it is the credibility artifact and already Kubernetes-free (`cmd/runner`).
3. First **real** integration = **MLflow**, via a generalized `ModelSource`
   interface (`List` / `Resolve` / `WriteBack`), live-tested against an `mlflow`
   container. Assert Quarantined + risk 100 + verdict written back as a tag.
4. Runtime scanning = KServe `InferenceService` admission gate + init-container
   scan-gate. Deferred until the MLflow path is solid. Registry scan and runtime
   scan are the **same pipeline, different triggers** — one spine, two triggers.
5. Langfuse = verdict×trace **correlation**, not model scanning — keep separate.

## Resume the live demo (after restarting Docker Desktop)
```
kind create cluster --name assay-demo        # if gone
make install                                  # CRDs under security.davano.io
# load images into kind: quay.io/davano/assay-operator:0.1.0 + scanner-*:0.1.0
make -C scanners ...                          # or docker tag + kind load
# run operator (out-of-cluster is fine): go run ./cmd/manager --enable-webhook=false ...
# UI: kubectl proxy --port=8903 --www=./ui --www-prefix=/ui/
```
