package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ArtifactScanSpec describes one scan of one model artifact.
type ArtifactScanSpec struct {
	// ModelName is the registered model name in the Model Registry.
	// +optional
	ModelName string `json:"modelName,omitempty"`
	// ModelVersion is the model version name.
	// +optional
	ModelVersion string `json:"modelVersion,omitempty"`
	// RegistryModelID is the registry's internal id for the model.
	// +optional
	RegistryModelID string `json:"registryModelID,omitempty"`
	// RegistryVersionID is the registry's internal id for the version.
	// +optional
	RegistryVersionID string `json:"registryVersionID,omitempty"`

	// ConnectorRef names the ModelRegistryConnector that created this scan.
	// +optional
	ConnectorRef string `json:"connectorRef,omitempty"`

	// Artifact is the artifact to scan.
	Artifact ArtifactRef `json:"artifact"`

	// PolicyRef names the ArtifactScanPolicy governing this scan.
	// +optional
	PolicyRef string `json:"policyRef,omitempty"`

	// Scanners overrides the policy's scanner set when non-empty.
	// +optional
	Scanners []string `json:"scanners,omitempty"`
}

// ArtifactScanStatus tracks scan execution and outcome.
type ArtifactScanStatus struct {
	// +kubebuilder:validation:Enum=Pending;Fetching;Scanning;Completed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// +optional
	Results []ScannerResult `json:"results,omitempty"`
	// RiskScore is 0 (clean) to 100 (critical risk).
	// +optional
	RiskScore *int32 `json:"riskScore,omitempty"`
	// +kubebuilder:validation:Enum=Approved;Quarantined;ReviewRequired;Unknown
	// +optional
	Verdict string `json:"verdict,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelName`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.modelVersion`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Verdict",type=string,JSONPath=`.status.verdict`
// +kubebuilder:printcolumn:name="Risk",type=integer,JSONPath=`.status.riskScore`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ArtifactScan is a request to scan one model artifact.
type ArtifactScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ArtifactScanSpec `json:"spec,omitempty"`
	// +optional
	Status ArtifactScanStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactScanList contains a list of ArtifactScan.
type ArtifactScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArtifactScan{}, &ArtifactScanList{})
}
