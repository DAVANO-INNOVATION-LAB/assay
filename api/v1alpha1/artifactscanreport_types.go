package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.scanner`
// +kubebuilder:printcolumn:name="Scan",type=string,JSONPath=`.scanRef`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.summary.status`
// +kubebuilder:printcolumn:name="Findings",type=integer,JSONPath=`.summary.findings`

// ArtifactScanReport holds the detailed findings of a single scanner run.
// Detailed data lives here so ArtifactScan and ModelSecurityReport stay small.
type ArtifactScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Scanner that produced this report.
	// +optional
	Scanner string `json:"scanner,omitempty"`
	// ScanRef names the owning ArtifactScan.
	// +optional
	ScanRef string `json:"scanRef,omitempty"`
	// +optional
	Summary ScannerResult `json:"summary,omitempty"`
	// +optional
	Findings []Finding `json:"findings,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactScanReportList contains a list of ArtifactScanReport.
type ArtifactScanReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactScanReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArtifactScanReport{}, &ArtifactScanReportList{})
}
