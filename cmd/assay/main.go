// Command assay is the standalone Assay CLI. It runs the same model-format
// inspector and policy engine the in-cluster operator uses, with no cluster
// required:
//
//	assay inspect <path>   scan a model file or directory and print a verdict
//	assay version          print the build version
//
// Exit codes are made for CI gates: 0 the artifact was Approved, 2 the
// verdict is ReviewRequired, 3 the verdict is Quarantined, and 1 means the
// scan itself failed. A finding is not an error: the scan completing with a
// bad verdict exits with the verdict's code, never 1.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/policy"
)

// version is stamped by the linker: -ldflags "-X main.version=v0.2.0".
var version = "dev"

const (
	exitApproved       = 0
	exitError          = 1
	exitReviewRequired = 2
	exitQuarantined    = 3
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "inspect":
		os.Exit(runInspect(os.Args[2:]))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `assay - supply-chain scanner for ML model artifacts

Usage:
  assay inspect <path> [--json] [--max-files N]
  assay version

assay inspect scans a model file or directory for the ways a model artifact
can execute code: unsafe serialization (pickle and friends), archive escapes,
executable payloads, and configs that hand execution to model-supplied code.

Exit codes: 0 Approved, 2 ReviewRequired, 3 Quarantined, 1 scan error.
`)
}

// jsonOutput is the machine-readable result of assay inspect.
type jsonOutput struct {
	Path         string                          `json:"path"`
	Verdict      string                          `json:"verdict"`
	RiskScore    int32                           `json:"riskScore"`
	FilesScanned int                             `json:"filesScanned"`
	Formats      []string                        `json:"formats,omitempty"`
	Severities   securityv1alpha1.SeverityCounts `json:"severities"`
	Violations   []string                        `json:"violations,omitempty"`
	Findings     []securityv1alpha1.Finding      `json:"findings"`
	Version      string                          `json:"assayVersion"`
}

func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the full report as JSON")
	maxFiles := fs.Int("max-files", 0, "cap on files examined (0 = default limits)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: assay inspect <path> [--json] [--max-files N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitError
	}
	path := fs.Arg(0)

	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "assay inspect: %v\n", err)
		return exitError
	}

	limits := inspector.DefaultLimits()
	if *maxFiles > 0 {
		limits.MaxFiles = *maxFiles
	}

	report, err := inspector.Inspect(path, limits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "assay inspect: %v\n", err)
		return exitError
	}

	severities := countSeverities(report.Findings)

	// Feed the findings through the same policy engine the operator runs, so
	// the CLI's verdict is the verdict a cluster would reach with the default
	// (nil) policy.
	result := securityv1alpha1.ScannerResult{
		Scanner:    "model-inspector",
		Status:     "Passed",
		Findings:   int32(len(report.Findings)),
		Severities: severities,
	}
	if len(report.Findings) > 0 {
		result.Status = "Failed"
	}
	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: path, Format: primaryFormat(report.Formats)},
		nil, nil, time.Now(),
	)

	if *jsonOut {
		out := jsonOutput{
			Path:         path,
			Verdict:      eval.Verdict,
			RiskScore:    eval.RiskScore,
			FilesScanned: report.FilesScanned,
			Formats:      report.Formats,
			Severities:   severities,
			Findings:     report.Findings,
			Version:      version,
		}
		for _, v := range eval.Violations {
			out.Violations = append(out.Violations, v.String())
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "assay inspect: %v\n", err)
			return exitError
		}
	} else {
		printHuman(path, report, severities, eval)
	}

	switch eval.Verdict {
	case securityv1alpha1.VerdictQuarantined:
		return exitQuarantined
	case securityv1alpha1.VerdictReviewRequired:
		return exitReviewRequired
	default:
		return exitApproved
	}
}

// severityRank orders findings most-severe-first in human output.
var severityRank = map[string]int{
	"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4,
}

func printHuman(path string, report *inspector.Report, severities securityv1alpha1.SeverityCounts, eval policy.Evaluation) {
	fmt.Printf("assay %s — %s\n", version, path)
	fmt.Printf("scanned %d file(s)", report.FilesScanned)
	if len(report.Formats) > 0 {
		fmt.Printf(", formats: %v", report.Formats)
	}
	fmt.Println()

	if len(report.Findings) == 0 {
		fmt.Println("\nno findings")
	} else {
		findings := append([]securityv1alpha1.Finding(nil), report.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
		})
		fmt.Println()
		for _, f := range findings {
			fmt.Printf("  [%-8s] %s  %s\n", f.Severity, f.ID, f.Title)
			if f.Location != "" {
				fmt.Printf("             at %s\n", f.Location)
			}
			fmt.Printf("             %s\n", f.Description)
		}
		fmt.Printf("\nfindings: %d critical, %d high, %d medium, %d low\n",
			severities.Critical, severities.High, severities.Medium, severities.Low)
	}

	for _, v := range eval.Violations {
		fmt.Printf("policy violation: %s\n", v)
	}
	fmt.Printf("\nverdict: %s (risk score %d/100)\n", eval.Verdict, eval.RiskScore)
}

func countSeverities(findings []securityv1alpha1.Finding) securityv1alpha1.SeverityCounts {
	var counts securityv1alpha1.SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			counts.Critical++
		case "High":
			counts.High++
		case "Medium":
			counts.Medium++
		case "Low":
			counts.Low++
		default:
			counts.Unknown++
		}
	}
	return counts
}

// primaryFormat picks the format for the ArtifactRef when the artifact
// contains exactly one recognized model format; a mixed artifact stays
// unlabeled rather than mislabeled.
func primaryFormat(formats []string) string {
	if len(formats) == 1 {
		return formats[0]
	}
	return ""
}
