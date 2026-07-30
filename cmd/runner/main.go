// Command runner is the in-pod half of Zeus. Scan Jobs invoke it three ways:
//
//	fetch    resolve an artifact URI and stage the bytes into the workspace
//	inspect  run the built-in model-format scanner over the workspace
//	publish  parse a scanner's output and record an ArtifactScanReport
//
// Keeping these in one binary means the scan pod only needs the Zeus image
// plus the scanner image, and only the publish step ever holds cluster
// credentials.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/zeus-security/zeus-operator/api/v1alpha1"
	"github.com/zeus-security/zeus-operator/internal/inspector"
	"github.com/zeus-security/zeus-operator/internal/naming"
	"github.com/zeus-security/zeus-operator/internal/resolver"
	"github.com/zeus-security/zeus-operator/internal/results"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "fetch":
		err = runFetch(ctx, os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "publish":
		err = runPublish(ctx, os.Args[2:])
	case "verify-provenance":
		err = runVerifyProvenance(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "zeus-runner %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `zeus-runner - in-pod scan steps for Zeus Model Scanner

Usage:
  zeus-runner fetch   --uri URI --dest DIR [--metadata FILE]
  zeus-runner inspect --workspace DIR --out FILE
  zeus-runner publish --scan NAME --namespace NS --scanner NAME --format FMT --results FILE [--metadata FILE]
  zeus-runner verify-provenance --workspace DIR --out FILE
`)
}

// artifactMetadata is handed from the fetch step to the publish step through
// the shared results volume, so the recorded digest is the one actually
// scanned rather than one re-derived later.
type artifactMetadata struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	SizeBytes int64  `json:"sizeBytes"`
}

func runFetch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	uri := fs.String("uri", "", "artifact URI to resolve")
	dest := fs.String("dest", "/workspace", "directory to stage the artifact into")
	metadataPath := fs.String("metadata", "", "write resolved artifact metadata here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uri == "" {
		return fmt.Errorf("--uri is required")
	}

	reg := resolver.NewRegistry()
	if !reg.Supports(*uri) {
		return fmt.Errorf("no resolver for artifact URI %q", *uri)
	}

	start := time.Now()
	artifact, err := reg.Resolve(ctx, *uri, *dest)
	if err != nil {
		return err
	}
	fmt.Printf("staged %s (%d bytes, digest %s) in %s\n",
		artifact.URI, artifact.SizeBytes, artifact.Digest, time.Since(start).Round(time.Millisecond))

	if *metadataPath != "" {
		metadata := artifactMetadata{
			URI:       artifact.URI,
			Digest:    artifact.Digest,
			MediaType: artifact.MediaType,
			SizeBytes: artifact.SizeBytes,
		}
		if err := writeJSON(*metadataPath, metadata); err != nil {
			return err
		}
	}
	return nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	workspace := fs.String("workspace", "/workspace", "staged artifact directory")
	out := fs.String("out", "", "write the findings report here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	report, err := inspector.Inspect(*workspace, inspector.DefaultLimits())
	if err != nil {
		return err
	}
	fmt.Printf("inspected %d files, %d findings, formats %v\n",
		report.FilesScanned, len(report.Findings), report.Formats)

	// The inspector exits 0 even when it finds problems: the verdict is the
	// controller's to make, and a non-zero exit would mark the Job failed and
	// lose the findings.
	return writeJSON(*out, report)
}

// runVerifyProvenance is the provenance scanner's entry point. Signature
// verification against TrustedPublishers is Phase 2; the step currently
// records that no verified attestation was found so policies requiring one
// fail closed rather than passing by omission.
func runVerifyProvenance(args []string) error {
	fs := flag.NewFlagSet("verify-provenance", flag.ExitOnError)
	workspace := fs.String("workspace", "/workspace", "staged artifact directory")
	out := fs.String("out", "", "write the findings report here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	_ = workspace

	report := struct {
		Findings []securityv1alpha1.Finding `json:"findings"`
	}{
		Findings: []securityv1alpha1.Finding{{
			ID:          "ZEUS-PROV-001",
			Title:       "No verified signature",
			Severity:    "Medium",
			Category:    "provenance",
			Description: "cosign verification against TrustedPublishers is not yet implemented; treat provenance as unverified",
		}},
	}
	return writeJSON(*out, report)
}

func runPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	scanName := fs.String("scan", "", "ArtifactScan this report belongs to")
	namespace := fs.String("namespace", "", "namespace of the ArtifactScan")
	scannerName := fs.String("scanner", "", "scanner that produced the results")
	format := fs.String("format", "", "result format")
	resultsPath := fs.String("results", "", "scanner output file")
	metadataPath := fs.String("metadata", "", "artifact metadata written by the fetch step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"--scan": *scanName, "--namespace": *namespace,
		"--scanner": *scannerName, "--format": *format, "--results": *resultsPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load cluster config: %w", err)
	}
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	status := "Passed"
	message := ""
	parsed, err := results.Parse(*format, *resultsPath)
	if err != nil {
		// A parse failure must not look like a clean scan.
		status = "Error"
		message = err.Error()
		parsed = &results.Parsed{}
	} else if parsed.Severities.Total() > 0 {
		status = "Failed"
		message = fmt.Sprintf("%d findings", parsed.Severities.Total())
	}

	now := metav1.Now()
	report := &securityv1alpha1.ArtifactScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.ScanReport(*scanName, *scannerName),
			Namespace: *namespace,
			Labels: map[string]string{
				"security.zeus.io/scan":    *scanName,
				"security.zeus.io/scanner": *scannerName,
			},
		},
		Scanner: *scannerName,
		ScanRef: *scanName,
		Summary: securityv1alpha1.ScannerResult{
			Scanner:        *scannerName,
			Status:         status,
			Findings:       parsed.Severities.Total(),
			Severities:     parsed.Severities,
			Message:        message,
			CompletionTime: &now,
		},
		Findings: parsed.Findings,
	}

	if *metadataPath != "" {
		if metadata, err := readMetadata(*metadataPath); err == nil && metadata.Digest != "" {
			if report.Annotations == nil {
				report.Annotations = map[string]string{}
			}
			report.Annotations["security.zeus.io/artifact-digest"] = metadata.Digest
			report.Annotations["security.zeus.io/artifact-uri"] = metadata.URI
		}
	}

	if err := k8s.Create(ctx, report); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create scan report: %w", err)
		}
		// A retried Job re-publishes; overwrite the previous attempt.
		existing := &securityv1alpha1.ArtifactScanReport{}
		key := client.ObjectKey{Name: report.Name, Namespace: report.Namespace}
		if err := k8s.Get(ctx, key, existing); err != nil {
			return fmt.Errorf("get existing scan report: %w", err)
		}
		report.ResourceVersion = existing.ResourceVersion
		if err := k8s.Update(ctx, report); err != nil {
			return fmt.Errorf("update scan report: %w", err)
		}
	}

	fmt.Printf("published %s report for scan %s: %s (%d findings)\n",
		*scannerName, *scanName, status, parsed.Severities.Total())
	return nil
}

func readMetadata(path string) (artifactMetadata, error) {
	var metadata artifactMetadata
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata, err
	}
	err = json.Unmarshal(data, &metadata)
	return metadata, err
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
