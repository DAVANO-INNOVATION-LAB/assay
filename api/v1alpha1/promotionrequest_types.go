package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PromotionRequestSpec asks to promote a model version to an environment.
type PromotionRequestSpec struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	// +kubebuilder:validation:Enum=dev;stage;prod
	TargetEnvironment string `json:"targetEnvironment"`
	// +optional
	Requestor string `json:"requestor,omitempty"`
	// +optional
	Justification string `json:"justification,omitempty"`
}

// PromotionRequestStatus tracks the approval workflow.
type PromotionRequestStatus struct {
	// +kubebuilder:validation:Enum=Pending;Approved;Rejected
	// +optional
	Phase string `json:"phase,omitempty"`
	// +optional
	ReviewedBy string `json:"reviewedBy,omitempty"`
	// +optional
	ReviewTime *metav1.Time `json:"reviewTime,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelName`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.modelVersion`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetEnvironment`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// PromotionRequest asks to promote a model version to an environment.
type PromotionRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PromotionRequestSpec `json:"spec,omitempty"`
	// +optional
	Status PromotionRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PromotionRequestList contains a list of PromotionRequest.
type PromotionRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PromotionRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PromotionRequest{}, &PromotionRequestList{})
}
