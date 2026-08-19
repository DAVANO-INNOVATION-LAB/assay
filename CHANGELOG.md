# Changelog

## v0.2.0

Six features, and a version's worth of claims that turned out not to be true
yet. Most of what follows is Assay being made to do what it already said it
did.

### The model itself is now described

Assay imports [Tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera) and
produces a **CycloneDX 1.6 ML-BOM and an SPDX 3.0.1 document** from the model's
own binary headers — architecture, measured parameter count, precision, tensor
shapes, licence, declared lineage, per-file hashes. The only bill of materials
before this was syft's SPDX of the packages *around* a model, of which the
controller parsed the package count.

**Drift** arrives with it: a config advertising a precision the tensors do not
carry is not a parse error and not a vulnerability, it is the artifact being
something other than what it says it is. `blockModelDrift` gates on it, off by
default — a quantized re-upload carrying its original config is the common
case, and a scanner that quarantines the common case gets switched off.

Pinned to Tessera v0.3.0, so the documents also carry **SHA-512** and the
**BSI TR-03183-2** component properties (`executable`, `archive`, `structured`,
`filename`) — the specification an assessor works from while the Cyber
Resilience Act's own format implementing act remains unadopted.

`requireAIBOM` is **not** satisfied by the scanner having run. A
bill-of-materials scanner that examines an artifact it cannot describe finds
nothing and exits zero, which is byte-for-byte the result of describing a clean
model.

### Formats the scan claimed to see are now inspected

`.keras`, `.h5` and `.pb` were reported as present formats and examined by
nothing — a summary naming a format with an empty findings list, which reads
exactly like a clean result. Now covered:

- Keras **Lambda layers**, which carry a marshalled Python code object that
  runs on load.
- **CVE-2026-1462** (Keras before 3.13.2, CVSS 8.8): `TFSMLayer`
  unconditionally loads an external SavedModel from a path in the config,
  "even when `safe_mode=True`".
- **CVE-2025-1550** (Keras 3.0.0 to before 3.8.0): an altered `config.json`
  names arbitrary modules and functions to import and call during loading,
  bypassing `safe_mode`.
- TensorFlow SavedModel graph operations that reach outside the graph.

Detection prefers content over extension in both directions: an HDF5 file under
any name is inspected via its superblock magic, and a file named `.h5` whose
header is not HDF5 is itself reported.

### The gate sees workloads that never opted in

It used to admit anything unannotated with "no model reference; nothing for
assay to validate". For a Deployment running vLLM off a claim of weights, that
sentence was false — and it is the sentence an operator reads as a pass.
Serving intent is now read from images, environment variables, `--model` flags
and volume mounts across every common workload kind.

A scheme-qualified storage URI resolves to the real verdict. Intent without
identity is denied under `--require-report` and otherwise admitted with a
warning, counted as `allowed_unidentified_model` rather than `allowed`. It
deliberately does not guess: `/models/llama3` and `meta-llama/Llama-3-8B` both
split plausibly under the KServe convention and would address a report
describing a different artifact.

### Admission decisions reach the audit chain

`DeploymentBlocked` and `DeploymentAdmitted` existed from the beginning and
nothing called them. Every denial and every admission that happened *despite*
something — an unscanned model, a skip annotation, audit or warn mode — is now
sealed into the chain with the authenticated username. Routine approvals are
not recorded: fifty replicas is fifty admission requests, and the approval is
already implied by the verdict it rests on.

A failed chain write never changes the decision, and increments
`assay_audit_write_failures_total` so a chain that has stopped recording is
visible rather than assumed intact.

### The promotion workflow exists

`PromotionRequest` had a CRD, an approval workflow in its status, and no
controller — and the AI RMF mapping for MAP 3.5 already cited promotion as a
step "Assay records with an approver".

The controller decides what is *permissible*: a model whose verdict is not
Approved cannot be promoted, and no signature changes that. That is `Blocked`,
deliberately a different phase from `Rejected`. A person decides whether it
*should* happen; nothing auto-approves. The verdict is re-read when the
decision is acted on, so an approval signed on Tuesday cannot promote a model
quarantined on Wednesday.

Both admission signers are now in the Helm chart. Only the deployment gate was,
so a Helm install had no exception signer either and its waivers were
unattributable.

### The images are signed

Keyless cosign signing in the release workflow, by digest rather than by tag,
with `--recursive` so each platform's child manifest is covered. The job
verifies the signatures it just made, because a release that silently produced
none looks identical to one that did.

```
cosign verify \
  --certificate-identity-regexp '^https://github.com/DAVANO-INNOVATION-LAB/assay/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/davano-innovation-lab/assay-operator:0.2.0
```

A **Docker Hub mirror** at `docker.io/davanolab` publishes from the same job
when `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are set. It copies the manifest
rather than rebuilding, so both registries serve identical digests and one
signature covers both.

### Corrections

- `CVE-2024-34359` is **llama-cpp-python**, not llama.cpp. The unsandboxed
  Jinja2 environment was in the Python binding; llama.cpp had no template
  engine at the time and took its own parser CVE later.
- **MAP 2.1** now requires the model description as well as the inventory
  entry. It asks what task and method the system implements; an inventory
  entry recorded a file format, and a package SBOM does not answer it either.

### Compatibility

`v1alpha1` gains fields and no breaking changes. `PromotionRequestSpec` adds
`decision`, `decisionReason`, `decidedBy`, `decidedByGroups` and `decidedAt`;
`ScannerResult` adds `drift` and `produced`; `ModelSecurityReportStatus` adds
`aibomRef`; `PolicyRules` adds `requireAIBOM` and `blockModelDrift`.

The new `assay-promotion-signer` webhook has `failurePolicy: Fail`. If the
operator is not running, `PromotionRequest` creates will be rejected — which is
the intended behaviour, since an unattributable promotion is worse than none.

## v0.1.0

Initial public release.
