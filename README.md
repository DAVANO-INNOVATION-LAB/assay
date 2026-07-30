# Zeus Model Scanner

An OpenShift-native security platform for AI models. Zeus integrates directly
with the OpenShift AI Model Registry, scans every registered model version,
and blocks unapproved models at deployment time — the way Advanced Cluster
Security works for containers, but purpose-built for model artifacts.

## Why the Model Registry is the integration point

Watching ImageStreams only catches models that happen to be packaged as
container images. The Model Registry is where a model is *declared*, which
means Zeus sees a model the moment it is registered, before anything tries to
deploy it, and regardless of whether the bytes live in S3, ODF, a PVC, an OCI
registry, or a ModelCar image.

## Pipeline

```
Model Registry ──▶ ModelRegistryConnector ──▶ ArtifactScan
                                                   │
                       ┌───────────────────────────┤ one Job per scanner
                       ▼                           ▼
                 fetch (init)               scan (init)
              resolve URI, stage         malware / CVE / SBOM
              bytes into /workspace      secrets / model format
                       │                           │
                       └──────────┬────────────────┘
                                  ▼
                            publish (main)
                        ArtifactScanReport CR
                                  │
                                  ▼
                     policy evaluation ──▶ ModelSecurityReport
                                                   │
                     verdict written back to registry
                                                   │
                                                   ▼
                                        admission webhook gates deploy
```

## What is here

| Component | Package | State |
|---|---|---|
| Model Registry client | `internal/registry` | Working: list, paginate, patch properties |
| Artifact resolvers | `internal/resolver` | OCI, ModelCar, S3/ODF, PVC, HTTP |
| Scan orchestrator | `internal/controller` | Working: one Job per scanner |
| Model inspector | `internal/inspector` | Working: pickle, archive, format analysis |
| Result parsers | `internal/results` | Validated against real scanner output |
| Policy engine | `internal/policy` | Working: rules, exceptions, risk scoring |
| Admission gate | `internal/webhook` | Working: KServe, Deployments, Pods |
| Scanner images | `scanners/` | Built: ClamAV, Trivy, Syft, TruffleHog, Grype |
| Cosign verification | `cmd/runner` | Stub that fails closed |
| AI safety evaluation | — | Phase 2 |
| Console plugin | — | Phase 2 |

The operator builds, the test suite passes, the scanner images build and run,
and every scanner has been verified against a planted artifact with networking
disabled. What has not happened yet is a run against a live OpenShift cluster
with a real Model Registry.

## Scanner images

Each scanner ships as its own image under `scanners/`. They all expose the
same two-argument contract — staged artifact directory, output file — so the
operator never encodes any one tool's CLI, and a scanner can be swapped
without touching the controller. `internal/scanners/catalog_test.go` enforces
that the catalog and the images stay in agreement, including that the file the
scanner writes is the file the publish step reads.

```bash
make scanners
```

```bash
make scanners-smoke
```

The smoke test runs every image against an artifact planted with an EICAR
file, vulnerable dependency pins, and live-looking credentials, under the same
constraints the operator applies in-cluster: no network, read-only root
filesystem, non-root user, all capabilities dropped.

### Air-gap

Vulnerability and malware databases are baked in at build time, so a scan
needs no egress at all — refreshing signatures means rebuilding the image.
That is the right tradeoff for a disconnected cluster: the alternative is a
scanner that silently reports clean because it could not reach its mirrors.
The ClamAV entrypoint refuses to run against an empty signature database for
the same reason.

To mirror into a disconnected registry:

```bash
make mirror-list
```

Then point the operator at the mirror with `--scanner-registry`. Image
references are resolved at Job build time, so nothing in the catalog is
pinned to a host the cluster cannot reach.

Image tags are pinned rather than `:latest` — a recorded verdict has to keep
meaning the same thing on a later scan.

### Parser fixtures

`internal/results/testdata/real_*` holds verbatim output captured from these
images. The hand-written tests check the formats the parsers expect; the
fixture tests check the formats the tools actually emit, which is the only
thing that catches an assumption that was wrong from the start. Refresh them
after bumping a scanner version:

```bash
make scanner-fixtures
```

## The model inspector

This is the part a generic container scanner cannot do. Trivy sees a model as
an opaque blob; the inspector understands the serialization formats:

- **Pickle analysis** — flags `GLOBAL`/`REDUCE` opcodes and dangerous imports
  (`os.system`, `subprocess.Popen`, `builtins.eval`) in `.pkl`, `.joblib`, and
  in pickles nested inside `torch.save` zip archives.
- **Archive safety** — zip slip, symlink escapes, entry-count limits, and
  compression-ratio checks for zip bombs.
- **Hugging Face configs** — `trust_remote_code: true` and `auto_map`, both of
  which hand execution to model-supplied Python at load time.
- **Format validation** — safetensors header bounds, numpy object-dtype arrays
  (which are pickles in disguise), suspicious ONNX operators.
- **Hidden payloads** — ELF/PE/Mach-O binaries and shell scripts behind
  innocuous file extensions.

Detection is evidence-based rather than heuristic. A numeric `.npy` array or a
raw `.bin` tensor dump contains every pickle opcode byte by coincidence;
`internal/inspector/falsepositive_test.go` pins the inert cases that must stay
silent, because a scanner that cries wolf gets switched off.

## Security model of a scan

Scan pods handle bytes from an untrusted source, so the Job is split into
three steps with different privileges:

1. **fetch** (init container) — resolves the URI and stages bytes. Gets
   registry and storage credentials, no cluster API access.
2. **scan** (init container) — runs the scanner. No credentials at all, no
   cluster API access, read-only root filesystem, all capabilities dropped.
   A bounded `emptyDir` at `/tmp` is the only writable path, which is what
   lets the read-only root filesystem hold for tools that need scratch space.
3. **publish** (main container) — parses results and writes one
   `ArtifactScanReport`. Its ServiceAccount can create that one resource type
   and nothing else.

Because scan and publish are ordered init-then-main, publish only runs after
the scanner exits, and it is the single component in the pod holding a token.

## Custom resources

| Kind | Purpose |
|---|---|
| `ModelRegistryConnector` | Connection to a Model Registry; polls and syncs |
| `ArtifactScan` | One scan of one artifact; owns the scan Jobs |
| `ArtifactScanReport` | Detailed findings from one scanner |
| `ModelSecurityReport` | Consolidated posture per model version; the gate reads this |
| `ArtifactScanPolicy` | Scanner set, pass/fail rules, enforcement mode |
| `ArtifactException` | Time-boxed waiver for specific rules |
| `TrustedPublisher` | Signing identity whose artifacts are trusted |
| `PromotionRequest` | Approval workflow for dev → stage → prod |

Detailed findings stay in the cluster; only a summary is written back to the
registry.

## Quick start

Build and publish the operator and scanner images, then deploy:

```bash
make docker-build docker-push scanners scanners-push
```

```bash
make install deploy
```

Then point Zeus at a registry and give it a policy:

```bash
kubectl apply -f config/samples/policy.yaml
kubectl apply -f config/samples/connector.yaml
```

Opt a namespace into deployment gating:

```bash
kubectl label namespace my-models security.zeus.io/enforce=true
```

Watch what happens:

```bash
kubectl get artifactscans -n zeus-system -w
```

## Enforcement defaults

Two defaults are deliberately permissive so that installing Zeus cannot break
a running cluster, and both should be tightened once coverage is complete:

- `--require-report=false` admits models that have never been scanned. Set it
  to `true` once every model in the registry has a report.
- The webhook's `failurePolicy: Ignore` keeps a Zeus outage from blocking all
  model deployments. `Fail` is the stronger setting, because `Ignore` means
  anyone who can disrupt Zeus can also bypass the gate.

## Development

```bash
make test
```

Requires Go 1.24+. `make manifests` regenerates CRDs and RBAC from the
kubebuilder markers; `make generate` regenerates DeepCopy methods.

## Roadmap

**Phase 1 (current)** — registry connector, scan orchestration, malware and
CVE scanning, SBOM, admission gate.

**Phase 2** — cosign/Sigstore verification against `TrustedPublisher`, AI
safety evaluation (prompt injection, jailbreak, backdoor detection),
promotion workflows, OpenShift console plugin.

**Phase 3** — multi-cluster federation, Hugging Face / MLflow / Kubeflow
connectors, continuous compliance and runtime monitoring.
