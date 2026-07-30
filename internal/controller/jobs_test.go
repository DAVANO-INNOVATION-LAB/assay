package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/zeus-security/zeus-operator/api/v1alpha1"
	"github.com/zeus-security/zeus-operator/internal/scanners"
)

func testScan() *securityv1alpha1.ArtifactScan {
	return &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-fraud-v1", Namespace: "zeus-system"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName:    "fraud",
			ModelVersion: "v1",
			Artifact:     securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
		},
	}
}

func testJobConfig() JobConfig {
	return JobConfig{
		OperatorImage:   "quay.io/zeus-security/zeus-operator:0.1.0",
		ScannerRegistry: "registry.internal/zeus",
		ServiceAccount:  "zeus-scanner",
		WorkspaceSize:   resource.MustParse("50Gi"),
	}
}

func buildFor(t *testing.T, scanner string) (*corev1.PodSpec, scanners.Definition) {
	t.Helper()
	def, err := scanners.Get(scanner)
	if err != nil {
		t.Fatal(err)
	}
	job, err := buildScanJob(testScan(), def, nil, testJobConfig())
	if err != nil {
		t.Fatalf("buildScanJob: %v", err)
	}
	return &job.Spec.Template.Spec, def
}

// The scan pod runs three steps in order, and the ordering is what keeps the
// scanner container credential-free: fetch and scan are init containers, so
// publish — the only step with a cluster token — runs after both finish.
func TestScanPodStepOrdering(t *testing.T) {
	pod, _ := buildFor(t, "clamav")

	if len(pod.InitContainers) != 2 {
		t.Fatalf("init containers = %d, want fetch and scan", len(pod.InitContainers))
	}
	if pod.InitContainers[0].Name != "fetch" {
		t.Errorf("first init container = %q, want fetch", pod.InitContainers[0].Name)
	}
	if pod.InitContainers[1].Name != "scan" {
		t.Errorf("second init container = %q, want scan", pod.InitContainers[1].Name)
	}
	if len(pod.Containers) != 1 || pod.Containers[0].Name != "publish" {
		t.Fatalf("main containers = %v, want only publish", pod.Containers)
	}
}

func TestScannerImageResolvesAgainstConfiguredRegistry(t *testing.T) {
	pod, _ := buildFor(t, "trivy")

	want := "registry.internal/zeus/scanner-trivy:" + scanners.ImageTag
	if got := pod.InitContainers[1].Image; got != want {
		t.Errorf("scan image = %q, want %q", got, want)
	}
}

func TestRunnerBackedScannerUsesOperatorImage(t *testing.T) {
	pod, _ := buildFor(t, "model-inspector")

	if got := pod.InitContainers[1].Image; got != testJobConfig().OperatorImage {
		t.Errorf("scan image = %q, want the operator image", got)
	}
}

// The catalog's path placeholders must be substituted, or the scanner would
// be handed a literal "$(WORKSPACE)" and find nothing.
func TestPathPlaceholdersAreSubstituted(t *testing.T) {
	pod, def := buildFor(t, "trivy")

	args := pod.InitContainers[1].Args
	for _, arg := range args {
		if strings.Contains(arg, "$(") {
			t.Errorf("arg %q still contains an unsubstituted placeholder", arg)
		}
	}
	if len(args) != 2 {
		t.Fatalf("args = %v, want workspace and output", args)
	}
	if args[0] != workspacePath {
		t.Errorf("workspace arg = %q, want %q", args[0], workspacePath)
	}
	if want := resultsPath + "/" + def.OutputFile; args[1] != want {
		t.Errorf("output arg = %q, want %q", args[1], want)
	}
}

// The publish step must read the same file the scanner was told to write.
// A divergence here would parse an absent file as a clean result.
func TestPublishReadsTheFileTheScannerWrites(t *testing.T) {
	for _, scanner := range []string{"clamav", "trivy", "syft", "trufflehog"} {
		t.Run(scanner, func(t *testing.T) {
			pod, _ := buildFor(t, scanner)

			scanOutput := pod.InitContainers[1].Args[1]

			var publishResults string
			publishArgs := pod.Containers[0].Args
			for i, arg := range publishArgs {
				if arg == "--results" && i+1 < len(publishArgs) {
					publishResults = publishArgs[i+1]
				}
			}
			if publishResults == "" {
				t.Fatalf("publish step has no --results argument: %v", publishArgs)
			}
			if publishResults != scanOutput {
				t.Errorf("publish reads %q but the scanner writes %q", publishResults, scanOutput)
			}
		})
	}
}

// Scanner containers process untrusted bytes. Every hardening control matters,
// and a regression here would not surface as a test failure anywhere else.
func TestScanContainerIsHardened(t *testing.T) {
	pod, _ := buildFor(t, "clamav")

	for _, c := range append(append([]corev1.Container{}, pod.InitContainers...), pod.Containers...) {
		t.Run(c.Name, func(t *testing.T) {
			sc := c.SecurityContext
			if sc == nil {
				t.Fatal("no security context")
			}
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Error("privilege escalation is not disabled")
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Error("root filesystem is not read-only")
			}
			if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				t.Error("container may run as root")
			}
			if sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 {
				t.Error("capabilities are not dropped")
			}
		})
	}
}

// A read-only root filesystem only works if the tools have somewhere to write.
// Without a writable /tmp, Trivy and ClamAV fail at startup.
func TestScanContainerHasWritableTmp(t *testing.T) {
	pod, _ := buildFor(t, "trivy")

	var hasTmpVolume bool
	for _, v := range pod.Volumes {
		if v.Name == "tmp" {
			hasTmpVolume = true
			if v.EmptyDir == nil {
				t.Error("tmp volume is not an emptyDir")
			} else if v.EmptyDir.SizeLimit == nil {
				t.Error("tmp volume has no size limit; a scanner could fill the node")
			}
		}
	}
	if !hasTmpVolume {
		t.Fatal("no tmp volume; a read-only root filesystem would break the scanners")
	}

	for _, c := range pod.InitContainers {
		var mounted bool
		for _, m := range c.VolumeMounts {
			if m.MountPath == tmpPath {
				mounted = true
			}
		}
		if !mounted {
			t.Errorf("container %q has no writable %s", c.Name, tmpPath)
		}
	}
}

// Only the publish step should be able to reach the API server. If the scanner
// container could, untrusted model bytes would be one exploit away from a
// cluster token.
func TestOnlyPublishCarriesClusterCredentials(t *testing.T) {
	pod, _ := buildFor(t, "clamav")

	if pod.ServiceAccountName != "zeus-scanner" {
		t.Errorf("service account = %q, want the restricted scanner account", pod.ServiceAccountName)
	}

	scan := pod.InitContainers[1]
	for _, m := range scan.VolumeMounts {
		if strings.Contains(m.MountPath, "serviceaccount") {
			t.Errorf("scan container mounts a service account token at %q", m.MountPath)
		}
	}
	for _, e := range scan.Env {
		if strings.Contains(strings.ToUpper(e.Name), "TOKEN") {
			t.Errorf("scan container receives a token via env %q", e.Name)
		}
	}
}

// Storage credentials belong to the fetch step alone; the scanner never needs
// them, and handing them over would widen the blast radius of a scanner bug.
func TestStorageCredentialsGoOnlyToFetch(t *testing.T) {
	cfg := testJobConfig()
	cfg.StorageSecret = "model-storage"
	def, _ := scanners.Get("clamav")

	job, err := buildScanJob(testScan(), def, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec

	var fetchHasCreds bool
	for _, e := range pod.InitContainers[0].Env {
		if e.Name == "AWS_ACCESS_KEY_ID" {
			fetchHasCreds = true
		}
	}
	if !fetchHasCreds {
		t.Error("fetch step did not receive storage credentials")
	}

	for _, e := range pod.InitContainers[1].Env {
		if strings.HasPrefix(e.Name, "AWS_") {
			t.Errorf("scan container received storage credential %q", e.Name)
		}
	}
}

func TestJobIsBoundedAndCleanedUp(t *testing.T) {
	def, _ := scanners.Get("clamav")
	job, err := buildScanJob(testScan(), def, nil, testJobConfig())
	if err != nil {
		t.Fatal(err)
	}

	if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds <= 0 {
		t.Error("scan job has no deadline; a hung scanner would run forever")
	}
	if job.Spec.TTLSecondsAfterFinished == nil {
		t.Error("scan job has no TTL; completed jobs would accumulate")
	}
	if job.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Error("restart policy should be Never so a failing scan surfaces")
	}
}

func TestMissingOperatorImageIsAnError(t *testing.T) {
	cfg := testJobConfig()
	cfg.OperatorImage = ""
	def, _ := scanners.Get("clamav")

	if _, err := buildScanJob(testScan(), def, nil, cfg); err == nil {
		t.Fatal("built a job with no operator image configured")
	}
}

// A policy may override a scanner's image, which is how an operator pins a
// patched build or swaps in their own implementation.
func TestPolicyCanOverrideScannerImage(t *testing.T) {
	def, _ := scanners.Get("clamav")
	spec := &securityv1alpha1.ScannerSpec{Name: "clamav", Image: "registry.internal/custom-clamav:2.0"}

	job, err := buildScanJob(testScan(), def, spec, testJobConfig())
	if err != nil {
		t.Fatal(err)
	}

	if got := job.Spec.Template.Spec.InitContainers[1].Image; got != spec.Image {
		t.Errorf("scan image = %q, want the policy override %q", got, spec.Image)
	}
}
