package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScannerSpec configures one scanner in a policy.
type ScannerSpec struct {
	// Name of the scanner (clamav, model-inspector, trivy, syft, trufflehog, ...).
	Name string `json:"name"`
	// Image overrides the built-in image for this scanner.
	// +optional
	Image string `json:"image,omitempty"`
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Args overrides the scanner container arguments.
	// +optional
	Args []string `json:"args,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// TimeoutSeconds bounds the scan job. Defaults to 1800.
	// +optional
	TimeoutSeconds *int64 `json:"timeoutSeconds,omitempty"`
}

// PolicyRules are the pass/fail gates evaluated after scanning.
type PolicyRules struct {
	// MaxCriticalCVEs above which the artifact is quarantined. Nil = no limit.
	// +optional
	MaxCriticalCVEs *int32 `json:"maxCriticalCVEs,omitempty"`
	// +optional
	MaxHighCVEs *int32 `json:"maxHighCVEs,omitempty"`
	// BlockMalware quarantines on any malware finding. Defaults to true.
	// +optional
	BlockMalware *bool `json:"blockMalware,omitempty"`
	// BlockSecrets quarantines on any leaked-secret finding. Defaults to true.
	// +optional
	BlockSecrets *bool `json:"blockSecrets,omitempty"`
	// BlockUnsafeModel quarantines on a critical model-inspection finding —
	// a pickle that imports os.system, an archive that escapes its directory,
	// trust_remote_code. These execute on load, so they are as serious as
	// malware. Defaults to true.
	// +optional
	BlockUnsafeModel *bool `json:"blockUnsafeModel,omitempty"`
	// RequireSignature demands a verified Cosign signature from a TrustedPublisher.
	// +optional
	RequireSignature bool `json:"requireSignature,omitempty"`
	// RequireSBOM demands a generated SBOM before approval.
	// +optional
	RequireSBOM bool `json:"requireSBOM,omitempty"`
	// RequireProvenance demands verified provenance attestations.
	// +optional
	RequireProvenance bool `json:"requireProvenance,omitempty"`
	// AllowedFormats restricts model formats (e.g. safetensors, onnx, gguf).
	// +optional
	AllowedFormats []string `json:"allowedFormats,omitempty"`
	// BlockedFormats quarantines specific formats (e.g. pickle).
	// +optional
	BlockedFormats []string `json:"blockedFormats,omitempty"`
}

// ArtifactScanPolicySpec defines scanners to run and rules to enforce.
type ArtifactScanPolicySpec struct {
	// +optional
	Scanners []ScannerSpec `json:"scanners,omitempty"`
	// +optional
	Rules PolicyRules `json:"rules,omitempty"`
	// Enforcement controls admission behavior for artifacts failing this
	// policy: Enforce rejects, Warn admits with a warning, Audit only logs.
	// +kubebuilder:validation:Enum=Enforce;Warn;Audit
	// +kubebuilder:default=Enforce
	// +optional
	Enforcement string `json:"enforcement,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Enforcement",type=string,JSONPath=`.spec.enforcement`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ArtifactScanPolicy configures scanning and gating for model artifacts.
type ArtifactScanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ArtifactScanPolicySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactScanPolicyList contains a list of ArtifactScanPolicy.
type ArtifactScanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactScanPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArtifactScanPolicy{}, &ArtifactScanPolicyList{})
}
