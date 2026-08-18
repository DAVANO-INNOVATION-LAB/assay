package audit

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

func testRecorder(t *testing.T) *Recorder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &Recorder{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		Namespace: "assay-system",
	}
}

func TestAppendBuildsAVerifiableChain(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	if _, err := r.Append(ctx, RiskAccepted("fraud", "v3", "alice@davano.net", "compensating control", []string{"CVE-1"}, "sha256:abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(ctx, VerdictIssued("fraud", "v4", "Quarantined", 87, "sha256:def")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(ctx, DeploymentDecision("fraud", "v4", "prod", "Deployment/api", false, "quarantined")); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("a freshly written chain must verify: %v", v.Problems)
	}
	if v.Length != 3 {
		t.Fatalf("want 3 records, got %d", v.Length)
	}
}

// The checkpoint must track the chain, or truncation stops being detectable.
func TestCheckpointFollowsTheChain(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if _, err := r.Append(ctx, VerdictIssued("m", "v", "Approved", 0, "")); err != nil {
			t.Fatal(err)
		}
	}
	_, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil {
		t.Fatal("no checkpoint was published")
	}
	if cp.Length != 4 {
		t.Fatalf("checkpoint should record 4 records, got %d", cp.Length)
	}
}

// Deleting a record must be caught. This is the scenario the whole package
// exists for: somebody removing the record of a decision they made.
func TestDeletingARecordIsDetectedInCluster(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := r.Append(ctx, RiskAccepted("m", "v", "bob", "because", nil, "")); err != nil {
			t.Fatal(err)
		}
	}

	// Remove the third record, as somebody covering their tracks would.
	var victim securityv1alpha1.AuditRecord
	key := client.ObjectKey{Name: recordName(3), Namespace: "assay-system"}
	if err := r.Client.Get(ctx, key, &victim); err != nil {
		t.Fatal(err)
	}
	if err := r.Client.Delete(ctx, &victim); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		t.Fatal("deleting an audit record must not verify")
	}
}

// Editing a record in place must be caught even though Kubernetes allowed the
// write — RBAC is the first line, the chain is the one that does not depend on
// RBAC being configured correctly.
func TestEditingARecordIsDetectedInCluster(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	if _, err := r.Append(ctx, RiskAccepted("m", "v", "mallory", "looked fine", nil, "")); err != nil {
		t.Fatal(err)
	}

	var rec securityv1alpha1.AuditRecord
	key := client.ObjectKey{Name: recordName(1), Namespace: "assay-system"}
	if err := r.Client.Get(ctx, key, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Spec.Actor = "alice"
	if err := r.Client.Update(ctx, &rec); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		t.Fatal("rewriting the actor on a record must not verify")
	}
}

func TestRecordsRoundTripThroughTheAPIShape(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	original, err := r.Append(ctx, RiskAccepted("fraud", "v3", "alice", "reviewed", []string{"B", "A"}, "sha256:xyz"))
	if err != nil {
		t.Fatal(err)
	}

	records, _, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	got := records[0]
	if got.Hash != original.Hash {
		t.Fatal("the hash did not survive storage; the chain would never verify")
	}
	if got.ComputeHash() != got.Hash {
		t.Fatal("a record read back from storage must still hash to its stored hash")
	}
	// Findings are sorted when recorded, so the same set in a different order
	// produces the same record rather than a spurious difference.
	if got.Detail["findings"] != "A,B" {
		t.Fatalf("findings should be sorted, got %q", got.Detail["findings"])
	}
}

func TestCheckpointRefusesToRegress(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := r.Append(ctx, VerdictIssued("m", "v", "Approved", 0, "")); err != nil {
			t.Fatal(err)
		}
	}
	// A shorter chain must not be allowed to re-bless the checkpoint.
	err := r.checkpoint(ctx, nil)
	if err == nil {
		t.Fatal("the checkpoint must refuse to move backwards, or truncation becomes re-blessable")
	}
}
