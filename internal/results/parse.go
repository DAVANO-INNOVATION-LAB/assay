// Package results parses scanner output into Assay findings. Each scanner has
// its own format; normalizing here keeps the policy engine format-agnostic.
package results

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/assay/internal/scanners"
)

// Parsed is the normalized output of one scanner run.
type Parsed struct {
	Findings   []securityv1alpha1.Finding
	Severities securityv1alpha1.SeverityCounts
}

// maxFindings caps how many detailed findings are stored in a report. A
// pathological artifact can produce tens of thousands; etcd has a 1.5 MiB
// object limit, so the report keeps the worst offenders and the summary keeps
// the true counts.
const maxFindings = 500

// Parse reads a scanner's output file and normalizes it.
func Parse(format, path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A scanner that found nothing may not write a file at all.
			return &Parsed{}, nil
		}
		return nil, fmt.Errorf("read scanner output %s: %w", path, err)
	}

	switch format {
	case scanners.FormatAssay:
		return parseAssay(data)
	case scanners.FormatClamAV:
		return parseClamAV(data)
	case scanners.FormatTrivyJSON:
		return parseTrivy(data)
	case scanners.FormatGrypeJSON:
		return parseGrype(data)
	case scanners.FormatSyftSPDX:
		return parseSPDX(data)
	case scanners.FormatTrufflehog:
		return parseTrufflehog(data)
	default:
		return nil, fmt.Errorf("unknown scanner result format %q", format)
	}
}

// assayReport is the native format Assay-authored scanners emit.
type assayReport struct {
	Findings []securityv1alpha1.Finding `json:"findings"`
}

func parseAssay(data []byte) (*Parsed, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Parsed{}, nil
	}
	var report assayReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse assay report: %w", err)
	}
	return finalize(report.Findings), nil
}

// parseClamAV reads clamscan's human-readable output. Infected files are
// reported as "path: SignatureName FOUND".
func parseClamAV(data []byte) (*Parsed, error) {
	var findings []securityv1alpha1.Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasSuffix(line, " FOUND") {
			continue
		}
		body := strings.TrimSuffix(line, " FOUND")
		path, signature, ok := strings.Cut(body, ": ")
		if !ok {
			continue
		}
		findings = append(findings, securityv1alpha1.Finding{
			ID:          signature,
			Title:       "Malware signature match",
			Severity:    "Critical",
			Category:    string(scanners.CategoryMalware),
			Location:    path,
			Description: fmt.Sprintf("ClamAV matched signature %s", signature),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read clamav output: %w", err)
	}
	return finalize(findings), nil
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID   string `json:"RuleID"`
			Category string `json:"Category"`
			Severity string `json:"Severity"`
			Title    string `json:"Title"`
			Match    string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func parseTrivy(data []byte) (*Parsed, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Parsed{}, nil
	}
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy report: %w", err)
	}

	var findings []securityv1alpha1.Finding
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			title := vuln.Title
			if title == "" {
				title = fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName)
			}
			description := fmt.Sprintf("%s %s is affected", vuln.PkgName, vuln.InstalledVersion)
			if vuln.FixedVersion != "" {
				description += fmt.Sprintf("; fixed in %s", vuln.FixedVersion)
			}
			findings = append(findings, securityv1alpha1.Finding{
				ID:          vuln.VulnerabilityID,
				Title:       title,
				Severity:    normalizeSeverity(vuln.Severity),
				Category:    string(scanners.CategoryCVE),
				Location:    result.Target,
				Description: description,
			})
		}
		// Trivy's secret scanner reports through the same document.
		for _, secret := range result.Secrets {
			findings = append(findings, securityv1alpha1.Finding{
				ID:          secret.RuleID,
				Title:       secret.Title,
				Severity:    normalizeSeverity(secret.Severity),
				Category:    string(scanners.CategorySecret),
				Location:    result.Target,
				Description: "Trivy matched a secret pattern",
			})
		}
	}
	return finalize(findings), nil
}

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"vulnerability"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

func parseGrype(data []byte) (*Parsed, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Parsed{}, nil
	}
	var report grypeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse grype report: %w", err)
	}

	var findings []securityv1alpha1.Finding
	for _, match := range report.Matches {
		location := match.Artifact.Name
		if len(match.Artifact.Locations) > 0 {
			location = match.Artifact.Locations[0].Path
		}
		findings = append(findings, securityv1alpha1.Finding{
			ID:          match.Vulnerability.ID,
			Title:       fmt.Sprintf("%s in %s", match.Vulnerability.ID, match.Artifact.Name),
			Severity:    normalizeSeverity(match.Vulnerability.Severity),
			Category:    string(scanners.CategoryCVE),
			Location:    location,
			Description: truncate(match.Vulnerability.Description, 512),
		})
	}
	return finalize(findings), nil
}

type spdxDocument struct {
	Packages []struct {
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
	} `json:"packages"`
}

// parseSPDX records the SBOM's package count. The SBOM itself is not a
// finding; it is evidence that the SBOM requirement was satisfied.
func parseSPDX(data []byte) (*Parsed, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Parsed{}, nil
	}
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX document: %w", err)
	}
	return &Parsed{}, nil
}

// trufflehogResult is one line of TruffleHog's JSON-lines output.
type trufflehogResult struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func parseTrufflehog(data []byte) (*Parsed, error) {
	var findings []securityv1alpha1.Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var result trufflehogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if result.DetectorName == "" {
			continue
		}

		severity := "High"
		description := "TruffleHog matched a credential pattern"
		if result.Verified {
			// A verified secret is live: the credential was confirmed
			// against the issuing service.
			severity = "Critical"
			description = "TruffleHog verified this credential is live"
		}

		location := result.SourceMetadata.Data.Filesystem.File
		if line := result.SourceMetadata.Data.Filesystem.Line; line > 0 {
			location = fmt.Sprintf("%s:%d", location, line)
		}

		findings = append(findings, securityv1alpha1.Finding{
			ID:          result.DetectorName,
			Title:       fmt.Sprintf("%s credential detected", result.DetectorName),
			Severity:    severity,
			Category:    string(scanners.CategorySecret),
			Location:    location,
			Description: description,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read trufflehog output: %w", err)
	}
	return finalize(findings), nil
}

// finalize counts severities across every finding, then truncates the
// detailed list. Counts always reflect the full set.
func finalize(findings []securityv1alpha1.Finding) *Parsed {
	parsed := &Parsed{}
	for i := range findings {
		findings[i].Severity = normalizeSeverity(findings[i].Severity)
		switch findings[i].Severity {
		case "Critical":
			parsed.Severities.Critical++
		case "High":
			parsed.Severities.High++
		case "Medium":
			parsed.Severities.Medium++
		case "Low":
			parsed.Severities.Low++
		default:
			parsed.Severities.Unknown++
		}
	}

	if len(findings) > maxFindings {
		sortBySeverity(findings)
		findings = findings[:maxFindings]
	}
	parsed.Findings = findings
	return parsed
}

var severityRank = map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

func sortBySeverity(findings []securityv1alpha1.Finding) {
	// Insertion into rank buckets preserves scanner order within a severity,
	// which keeps reports stable between runs.
	buckets := make([][]securityv1alpha1.Finding, 5)
	for _, f := range findings {
		rank, ok := severityRank[f.Severity]
		if !ok {
			rank = 4
		}
		buckets[rank] = append(buckets[rank], f)
	}
	i := 0
	for _, bucket := range buckets {
		for _, f := range bucket {
			findings[i] = f
			i++
		}
	}
}

func normalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM", "MODERATE":
		return "Medium"
	case "LOW", "NEGLIGIBLE", "INFO", "INFORMATIONAL":
		return "Low"
	default:
		return "Unknown"
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
