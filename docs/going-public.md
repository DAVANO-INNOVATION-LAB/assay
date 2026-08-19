# Going public

Everything that can be done ahead of time has been. What remains are the steps
that *are* the publishing, plus one that needs a local git operation.

Work through it in order — the package visibility step depends on the repository
already being public.

## 1. Scrub the history (do this first, before anything is visible)

The repository still carries 36 `Co-Authored-By: Claude` trailers, the old
working name in a handful of commit messages, and 74MB of stale build artifacts
that make every clone heavier forever.

A backup bundle already exists at `~/m-dev/assay-backup.bundle` (verified
complete). To restore from it if anything goes wrong:

```bash
git fetch /Users/m/m-dev/assay-backup.bundle 'refs/*:refs/*'
```

The rewrite:

```bash
cd ~/m-dev/zeus
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --index-filter 'git rm --cached --ignore-unmatch -q runner assay ui/index.html' \
  --msg-filter 'python3 /Users/m/m-dev/assay-msgfilter.py' \
  --prune-empty -- --all
```

Check `git log` reads sensibly, then:

```bash
git push --force origin main
```

The message filter normalises the old working name but deliberately does not
invent history: the commit recording the move between GitHub organisations still
says a move happened, it just stops naming the old repository.

## 2. Make the repositories public

```bash
gh repo edit DAVANO-INNOVATION-LAB/assay --visibility public --accept-visibility-change-consequences
gh repo edit DAVANO-INNOVATION-LAB/docket --visibility public --accept-visibility-change-consequences
```

## 3. Make the packages public

**This is the step that breaks the install if it is missed.** Packages published
to GitHub Container Registry default to private, and a private package returns
`401 Unauthorized` to an anonymous pull — so every `helm install` and
`kubectl apply` fails at image pull for anyone who is not a member of the
organisation.

There is no REST endpoint for container package visibility; it is a web UI
operation. For each of these six packages:

<https://github.com/orgs/DAVANO-INNOVATION-LAB/packages>

- `assay-operator`
- `scanner-clamav`
- `scanner-trivy`
- `scanner-grype`
- `scanner-syft`
- `scanner-trufflehog`

Package → **Package settings** → **Danger Zone** → **Change visibility** →
Public.

The images carry `org.opencontainers.image.source` pointing at the repository,
so they will appear on the repository page once both are public.

Verify with an anonymous pull, from a shell with no Docker credentials:

```bash
docker logout ghcr.io
docker pull ghcr.io/davano-innovation-lab/assay-operator:0.1.0
```

## 4. Confirm a clean install works

The only real test is the one a stranger runs. From a scratch cluster:

```bash
kind create cluster --name assay-fresh
kubectl apply -k config/crd
helm install assay deploy/helm/assay -n assay-system --create-namespace
kubectl -n assay-system rollout status deploy/assay-controller-manager
```

Then scan something and confirm a verdict comes back. If the scanner Jobs sit in
`ImagePullBackOff`, step 3 was missed.

## Deliberately not done

**Image signing.** Assay verifies signatures on the models it scans and does not
yet publish signatures for its own images. That is a real gap, it is stated in
[SECURITY.md](../SECURITY.md), and the machinery to close it already exists in
`internal/provenance`. Closing it before a 1.0 would be consistent; claiming it
now would not.

**A Docker Hub mirror.** `docker.io/davanolab` is empty. The images are tagged
for it locally; publishing needs `docker login` from someone who holds those
credentials.

**`yara` and `license` scanners.** Present in the catalog, marked `Unbuilt`, no
image published. The console will not offer them, which is the intended
behaviour for a scanner whose image cannot be pulled.
