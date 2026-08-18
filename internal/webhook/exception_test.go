package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

func exception(mutate func(*securityv1alpha1.ArtifactException)) securityv1alpha1.ArtifactException {
	ex := securityv1alpha1.ArtifactException{
		ObjectMeta: metav1.ObjectMeta{Name: "waive-fraud-v3", Namespace: testNamespace},
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			ModelName:    "fraud-detector",
			ModelVersion: "v3.0.0",
			Rules:        []string{"blockUnsafeModel"},
			Reason:       "reviewed with the vendor; the pickle is a documented loader shim",
		},
	}
	if mutate != nil {
		mutate(&ex)
	}
	return ex
}

func signRequest(t *testing.T, ex securityv1alpha1.ArtifactException, user string, groups []string, op admissionv1.Operation, old *securityv1alpha1.ArtifactException) admission.Response {
	t.Helper()
	raw, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op,
		Object:    runtime.RawExtension{Raw: raw},
		UserInfo:  authenticationv1.UserInfo{Username: user, Groups: groups},
	}}
	if old != nil {
		oldRaw, err := json.Marshal(*old)
		if err != nil {
			t.Fatal(err)
		}
		req.OldObject = runtime.RawExtension{Raw: oldRaw}
	}
	return (&ExceptionSigner{}).Handle(context.Background(), req)
}

// applyPatches replays the admission patch onto the submitted object so the
// test asserts on what would actually be persisted, using a real JSON Patch
// implementation rather than a hand-rolled one — array paths and escaping are
// exactly where a naive replay diverges from what the API server does.
func applyPatches(t *testing.T, ex securityv1alpha1.ArtifactException, resp admission.Response) securityv1alpha1.ArtifactException {
	t.Helper()
	original, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(raw)
	if err != nil {
		t.Fatalf("decode admission patch: %v", err)
	}
	patched, err := patch.Apply(original)
	if err != nil {
		t.Fatalf("apply admission patch: %v", err)
	}
	var result securityv1alpha1.ArtifactException
	if err := json.Unmarshal(patched, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// The signature has to come from the authenticated request, not the payload.
// Otherwise "approvedBy" is a text field anyone can put anyone's name in.
func TestApproverCannotSignAsSomeoneElse(t *testing.T) {
	forged := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "head-of-security"
		e.Spec.ApprovedByGroups = []string{"secops"}
	})

	resp := signRequest(t, forged, "intern@corp.example", []string{"all-staff"}, admissionv1.Create, nil)
	if !resp.Allowed {
		t.Fatalf("valid exception was denied: %v", resp.Result)
	}

	got := applyPatches(t, forged, resp)
	if got.Spec.ApprovedBy != "intern@corp.example" {
		t.Errorf("approvedBy = %q; the claimed name was not replaced with the authenticated one", got.Spec.ApprovedBy)
	}
	if len(got.Spec.ApprovedByGroups) != 1 || got.Spec.ApprovedByGroups[0] != "all-staff" {
		t.Errorf("groups = %v; want the authenticated groups, not the submitted ones", got.Spec.ApprovedByGroups)
	}
	if got.Spec.ApprovedAt == nil {
		t.Error("no approval timestamp was stamped")
	}
}

// A waiver with no stated reason is indistinguishable from a mistake once
// whoever wrote it has moved on.
func TestUnexplainedWaiversAreRejected(t *testing.T) {
	cases := map[string]securityv1alpha1.ArtifactException{
		"no reason": exception(func(e *securityv1alpha1.ArtifactException) { e.Spec.Reason = "  " }),
		"no model":  exception(func(e *securityv1alpha1.ArtifactException) { e.Spec.ModelName = "" }),
		"waives nothing": exception(func(e *securityv1alpha1.ArtifactException) {
			e.Spec.Rules = nil
			e.Spec.FindingIDs = nil
		}),
	}
	for name, ex := range cases {
		if resp := signRequest(t, ex, "u", nil, admissionv1.Create, nil); resp.Allowed {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The audit trail is append-only: a signed acceptance cannot be reassigned to
// someone else, or the record stops meaning anything.
func TestSignatureCannotBeReassigned(t *testing.T) {
	original := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "alice@corp.example"
	})
	stolen := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "bob@corp.example"
	})

	resp := signRequest(t, stolen, "bob@corp.example", nil, admissionv1.Update, &original)
	if resp.Allowed {
		t.Error("a signed exception was reassigned to a different approver")
	}
	if !strings.Contains(resp.Result.Message, "alice@corp.example") {
		t.Errorf("denial does not name the original signer: %s", resp.Result.Message)
	}
}

// Quietly widening a signed waiver would let an approval of one narrow thing
// become cover for something never reviewed.
func TestSignedExceptionCannotBeWidened(t *testing.T) {
	original := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "alice@corp.example"
		e.Spec.Rules = []string{"blockUnsafeModel"}
	})
	widened := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "alice@corp.example"
		e.Spec.Rules = []string{"blockUnsafeModel", "blockMalware"}
	})

	if resp := signRequest(t, widened, "alice@corp.example", nil, admissionv1.Update, &original); resp.Allowed {
		t.Error("a signed exception was widened to cover a rule nobody approved")
	}

	// Narrowing is fine: it only ever reduces what was accepted.
	narrowed := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ApprovedBy = "alice@corp.example"
		e.Spec.Rules = []string{"blockUnsafeModel"}
	})
	if resp := signRequest(t, narrowed, "alice@corp.example", nil, admissionv1.Update, &original); !resp.Allowed {
		t.Errorf("narrowing a signed exception was denied: %v", resp.Result)
	}
}

// Binding the acceptance to the digest that was reviewed is what stops an
// approval carrying over to different bytes published at the same name.
func TestDigestBindingIsPreserved(t *testing.T) {
	ex := exception(func(e *securityv1alpha1.ArtifactException) {
		e.Spec.ScannedDigest = "sha256:1f0e3dad99908345f7439f8ffabdffc4"
	})
	resp := signRequest(t, ex, "alice@corp.example", []string{"secops"}, admissionv1.Create, nil)
	got := applyPatches(t, ex, resp)
	if got.Spec.ScannedDigest != ex.Spec.ScannedDigest {
		t.Errorf("digest binding = %q, want it preserved through signing", got.Spec.ScannedDigest)
	}
}
