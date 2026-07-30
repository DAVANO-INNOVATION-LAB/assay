package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ArtifactExceptionSpec waives specific policy failures for a model version.
type ArtifactExceptionSpec struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	// FindingIDs lists waived finding IDs (e.g. CVE-2025-1234). Empty with
	// Rules set waives whole rule categories instead.
	// +optional
	FindingIDs []string `json:"findingIDs,omitempty"`
	// Rules lists waived policy rule names (e.g. maxCriticalCVEs, requireSBOM).
	// +optional
	Rules  []string `json:"rules,omitempty"`
	Reason string   `json:"reason"`
	// +optional
	ApprovedBy string `json:"approvedBy,omitempty"`
	// ExpiresAt after which the exception no longer applies.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// ArtifactExceptionStatus tracks exception lifecycle.
type ArtifactExceptionStatus struct {
	// +kubebuilder:validation:Enum=Active;Expired
	// +optional
	Phase string `json:"phase,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelName`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.modelVersion`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.spec.expiresAt`

// ArtifactException waives specific policy failures for a model version.
type ArtifactException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ArtifactExceptionSpec `json:"spec,omitempty"`
	// +optional
	Status ArtifactExceptionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactExceptionList contains a list of ArtifactException.
type ArtifactExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactException `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArtifactException{}, &ArtifactExceptionList{})
}
