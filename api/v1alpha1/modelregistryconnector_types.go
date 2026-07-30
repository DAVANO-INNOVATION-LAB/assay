package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ModelRegistryConnectorSpec defines a connection to an OpenShift AI
// (Kubeflow) Model Registry instance to watch for models to scan.
type ModelRegistryConnectorSpec struct {
	// RegistryURL is the base URL of the Model Registry REST API,
	// e.g. https://model-registry.rhoai-model-registries.svc:8080
	RegistryURL string `json:"registryURL"`

	// AuthSecretRef references a Secret containing a bearer token used to
	// authenticate against the registry.
	// +optional
	AuthSecretRef *SecretKeyRef `json:"authSecretRef,omitempty"`

	// InsecureSkipTLSVerify disables TLS certificate verification.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// PollInterval controls how often the registry is polled for new
	// models and versions. Defaults to 1m.
	// +optional
	PollInterval *metav1.Duration `json:"pollInterval,omitempty"`

	// PolicyRef names the ArtifactScanPolicy applied to scans created by
	// this connector. Empty selects the built-in default scanner set.
	// +optional
	PolicyRef string `json:"policyRef,omitempty"`

	// IncludeModels restricts scanning to registered models whose name
	// matches one of these globs. Empty means all models.
	// +optional
	IncludeModels []string `json:"includeModels,omitempty"`

	// WriteBack controls whether scan summaries are written back into the
	// Model Registry as custom properties. Defaults to true.
	// +optional
	WriteBack *bool `json:"writeBack,omitempty"`
}

// ModelRegistryConnectorStatus reports sync progress.
type ModelRegistryConnectorStatus struct {
	// +kubebuilder:validation:Enum=Pending;Connected;Degraded;Error
	// +optional
	Phase string `json:"phase,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// +optional
	RegisteredModels int32 `json:"registeredModels,omitempty"`
	// +optional
	ModelVersions int32 `json:"modelVersions,omitempty"`
	// +optional
	ScansCreated int32 `json:"scansCreated,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mrc
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registryURL`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Models",type=integer,JSONPath=`.status.registeredModels`
// +kubebuilder:printcolumn:name="Scans",type=integer,JSONPath=`.status.scansCreated`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`

// ModelRegistryConnector connects Zeus to an OpenShift AI Model Registry.
type ModelRegistryConnector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ModelRegistryConnectorSpec `json:"spec,omitempty"`
	// +optional
	Status ModelRegistryConnectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ModelRegistryConnectorList contains a list of ModelRegistryConnector.
type ModelRegistryConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelRegistryConnector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ModelRegistryConnector{}, &ModelRegistryConnectorList{})
}
