package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PromotionRequestSpec asks to promote a model version to an environment.
//
// Requestor, DecidedBy and DecidedAt are stamped by the admission webhook from
// the authenticated request and whatever a submitter puts in them is discarded.
// That is the same rule ArtifactException follows and for the same reason: a
// name in a payload is a claim, and an approval nobody can attribute is not an
// approval.
type PromotionRequestSpec struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	// +kubebuilder:validation:Enum=dev;stage;prod
	TargetEnvironment string `json:"targetEnvironment"`
	// Requestor is stamped from the authenticated identity that created the
	// request.
	// +optional
	Requestor string `json:"requestor,omitempty"`
	// +optional
	Justification string `json:"justification,omitempty"`

	// Decision is the human step. Empty means nobody has decided yet, which is
	// the state a promotion request exists to hold: the controller can say
	// whether a promotion is *permissible*, and only a person can say whether
	// it should happen.
	// +kubebuilder:validation:Enum=Approve;Reject
	// +optional
	Decision string `json:"decision,omitempty"`
	// DecisionReason explains the decision. Required to reject, because an
	// unexplained refusal is indistinguishable from an oversight later.
	// +optional
	DecisionReason string `json:"decisionReason,omitempty"`
	// DecidedBy is stamped from the authenticated identity that set Decision.
	// +optional
	DecidedBy string `json:"decidedBy,omitempty"`
	// DecidedByGroups records the groups that identity belonged to.
	// +optional
	DecidedByGroups []string `json:"decidedByGroups,omitempty"`
	// DecidedAt is stamped when Decision is first set.
	// +optional
	DecidedAt *metav1.Time `json:"decidedAt,omitempty"`
}

// PromotionRequestStatus tracks the approval workflow.
type PromotionRequestStatus struct {
	// Phase is where the request has got to.
	//
	// Blocked is distinct from Rejected on purpose: one means a person said no,
	// the other means the model's own security verdict forbids the promotion
	// regardless of what anybody says. Collapsing them would make a policy
	// refusal look like a human decision.
	// +kubebuilder:validation:Enum=Pending;Approved;Rejected;Blocked
	// +optional
	Phase string `json:"phase,omitempty"`
	// Verdict is the security verdict this request was last evaluated against,
	// so a reviewer sees what they are approving rather than having to go and
	// look it up.
	// +optional
	Verdict string `json:"verdict,omitempty"`
	// ObservedVerdictTime is when that verdict was issued. An approval signed
	// against one verdict must not silently carry over to a later one.
	// +optional
	ObservedVerdictTime *metav1.Time `json:"observedVerdictTime,omitempty"`
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
// +kubebuilder:printcolumn:name="Verdict",type=string,JSONPath=`.status.verdict`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

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

// Promotion phases.
const (
	PromotionPending  = "Pending"
	PromotionApproved = "Approved"
	PromotionRejected = "Rejected"
	// PromotionBlocked means the model's security verdict forbids the
	// promotion. It is not a human decision and cannot be overridden by one.
	PromotionBlocked = "Blocked"
)

// Promotion decisions, as set by a reviewer in spec.decision.
const (
	DecisionApprove = "Approve"
	DecisionReject  = "Reject"
)
