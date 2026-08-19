# Security policy

## Reporting a vulnerability

Email **DAVANO@davano.net** with `[SECURITY]` in the subject. Please do not open
a public issue for a vulnerability.

Include what you need to make the problem reproducible: the version or image
digest, what you did, what happened, and what you expected. A proof of concept
helps but is not required to report something.

What to expect:

- An acknowledgement within **3 working days**. If you have not heard back in a
  week, assume the mail went astray and send it again — that is a failure on our
  side, not a reason to stay quiet.
- An assessment within **10 working days**, saying whether we agree it is a
  vulnerability and what severity we think it carries. If we disagree with your
  assessment we will say why rather than going silent.
- A fix or a documented mitigation for anything we accept as Critical or High
  within **30 days**, and a public advisory when it ships.

We will credit you in the advisory unless you ask us not to. This project has no
bug bounty.

## What counts as a vulnerability here

Assay is a security tool, which makes the boundary worth stating plainly.

**These are vulnerabilities. Please report them.**

- A way to make a scan report `Approved` for an artifact that should not be —
  particularly anything that gets a malicious pickle, an embedded credential or
  a malware detection past the policy engine.
- A way to get past the admission gate: a workload deployed with a model that
  has no verdict, a quarantined verdict, or a verdict belonging to different
  bytes.
- Any path where a scan fails and the result reads as clean rather than as
  failed. Assay is built to fail closed, and a fail-open path is the most
  serious class of bug this project has.
- Reading findings, model names or any other data outside your role and tenant
  through the console API.
- Anything that lets a scanned artifact execute code in the operator, the API
  server, or outside its own sandboxed scan Job. Scanners process hostile input
  by design; escaping that boundary is a real finding.
- Recording an acceptance without the approver's authenticated identity, or
  altering an audit record without breaking the chain.
- Credential disclosure: a token in a log, a Secret reaching a scan pod, a
  credential in an evidence bundle.

**These are not vulnerabilities, though they may still be bugs worth filing
publicly.**

- A model that is genuinely malicious in a way Assay does not detect, where the
  detection was never claimed. The limits are documented in
  [docs/](docs/) and in the ATLAS coverage mapping: weight-level poisoning,
  training-data poisoning, runtime evasion, and registry-history attacks like
  rug pulls are **out of scope by construction**, not by oversight. A scanner
  that inspects an artifact cannot see them.
- A false positive. Annoying, and we want to hear about it, but it fails closed.
- Findings against the demonstration console when it is run without TLS through
  a port-forward. That configuration is documented as a local convenience and
  warns at startup.
- Anything requiring cluster-admin to exploit. If you already have cluster-admin
  you do not need a vulnerability in Assay.

## Supported versions

Assay is pre-1.0. Only the latest tagged release receives fixes. There are no
long-term support branches yet.

## Verifying what you run

Images are published to `ghcr.io/davano-innovation-lab`. Pin by digest rather
than tag if you care about what you are running:

```bash
docker pull ghcr.io/davano-innovation-lab/assay-operator@sha256:<digest>
```

Assay verifies signatures on the models it scans. It does not yet publish
signatures for its own images — that is a gap we know about and intend to close
with the same Sigstore machinery, and until it does you should treat the images
as unsigned.
