package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

// CheckpointName is the singleton checkpoint object per namespace.
const CheckpointName = "assay-audit-head"

// Recorder appends to the audit chain stored as AuditRecord objects.
type Recorder struct {
	Client    client.Client
	Namespace string
}

// Append seals an event onto the end of the chain and persists it.
//
// Concurrency is handled by the API server rather than by a lock: the record
// name embeds its sequence number, so two writers racing for the same position
// collide on AlreadyExists and the loser retries against the new head. That
// keeps the chain linear without the operator holding a lease it could lose.
func (r *Recorder) Append(ctx context.Context, event Record) (*Record, error) {
	const attempts = 5
	var lastErr error

	for i := 0; i < attempts; i++ {
		records, err := r.load(ctx)
		if err != nil {
			return nil, err
		}
		var prev *Record
		if len(records) > 0 {
			prev = &records[len(records)-1]
		}

		sealed := Seal(event, prev)
		obj := &securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      recordName(sealed.Seq),
				Namespace: r.Namespace,
				Labels: map[string]string{
					"security.davano.io/audit-type": string(sealed.Type),
				},
			},
			Spec: securityv1alpha1.AuditRecordSpec{
				Seq:      int64(sealed.Seq),
				Time:     metav1.NewTime(sealed.Time),
				Type:     string(sealed.Type),
				Subject:  sealed.Subject,
				Actor:    sealed.Actor,
				Detail:   sealed.Detail,
				PrevHash: sealed.PrevHash,
				Hash:     sealed.Hash,
			},
		}

		err = r.Client.Create(ctx, obj)
		if err == nil {
			// Advance the checkpoint. A failure here leaves a correct chain
			// with a stale checkpoint, which is a detectable inconsistency
			// rather than a silent gap, so it does not fail the append.
			_ = r.checkpoint(ctx, append(records, sealed))
			return &sealed, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("append audit record: %w", err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("append audit record: lost %d races for the chain head: %w", attempts, lastErr)
}

// load reads the chain in sequence order.
func (r *Recorder) load(ctx context.Context) ([]Record, error) {
	var list securityv1alpha1.AuditRecordList
	if err := r.Client.List(ctx, &list, client.InNamespace(r.Namespace)); err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	records := make([]Record, 0, len(list.Items))
	for _, item := range list.Items {
		records = append(records, fromAPI(item))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Seq < records[j].Seq })
	return records, nil
}

// Chain returns the stored chain and its published checkpoint.
func (r *Recorder) Chain(ctx context.Context) ([]Record, *Checkpoint, error) {
	records, err := r.load(ctx)
	if err != nil {
		return nil, nil, err
	}

	var cpObj securityv1alpha1.AuditCheckpoint
	err = r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &cpObj)
	switch {
	case apierrors.IsNotFound(err):
		return records, nil, nil
	case err != nil:
		return nil, nil, err
	}
	cp := &Checkpoint{
		Length: uint64(cpObj.Spec.Length),
		Head:   cpObj.Spec.Head,
		Time:   cpObj.Spec.Time.Time,
	}
	return records, cp, nil
}

// Verify checks the stored chain against its published checkpoint.
func (r *Recorder) Verify(ctx context.Context) (Verification, error) {
	records, cp, err := r.Chain(ctx)
	if err != nil {
		return Verification{}, err
	}
	return Verify(records, cp), nil
}

// checkpoint publishes the new head.
func (r *Recorder) checkpoint(ctx context.Context, records []Record) error {
	cp := Head(records)
	obj := &securityv1alpha1.AuditCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: CheckpointName, Namespace: r.Namespace},
		Spec: securityv1alpha1.AuditCheckpointSpec{
			Length: int64(cp.Length),
			Head:   cp.Head,
			Time:   metav1.NewTime(cp.Time),
		},
	}

	var existing securityv1alpha1.AuditCheckpoint
	err := r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		return r.Client.Create(ctx, obj)
	case err != nil:
		return err
	}
	// Never move a checkpoint backwards. A checkpoint that can regress is not
	// a checkpoint: it would let a truncated log be re-blessed.
	if existing.Spec.Length > obj.Spec.Length {
		return fmt.Errorf("refusing to regress the checkpoint from %d to %d records",
			existing.Spec.Length, obj.Spec.Length)
	}
	existing.Spec = obj.Spec
	return r.Client.Update(ctx, &existing)
}

func fromAPI(item securityv1alpha1.AuditRecord) Record {
	return Record{
		Seq:      uint64(item.Spec.Seq),
		Time:     item.Spec.Time.Time.UTC(),
		Type:     EventType(item.Spec.Type),
		Subject:  item.Spec.Subject,
		Actor:    item.Spec.Actor,
		Detail:   item.Spec.Detail,
		PrevHash: item.Spec.PrevHash,
		Hash:     item.Spec.Hash,
	}
}

func recordName(seq uint64) string {
	return fmt.Sprintf("audit-%012d", seq)
}

// Subject formats a model and version as an audit subject.
func Subject(model, version string) string {
	if version == "" {
		return model
	}
	return model + "/" + version
}

// RiskAccepted builds the record for an accepted risk.
func RiskAccepted(model, version, actor, reason string, findings []string, digest string) Record {
	detail := map[string]string{"reason": reason}
	if len(findings) > 0 {
		sorted := append([]string{}, findings...)
		sort.Strings(sorted)
		detail["findings"] = strings.Join(sorted, ",")
	}
	// The digest binds the acceptance to the bytes that were reviewed. Without
	// it the record says a risk was accepted for a name, and names get reused.
	if digest != "" {
		detail["digest"] = digest
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    EventRiskAccepted,
		Subject: Subject(model, version),
		Actor:   actor,
		Detail:  detail,
	}
}

// VerdictIssued builds the record for a scan reaching a verdict.
func VerdictIssued(model, version, verdict string, risk int32, digest string) Record {
	detail := map[string]string{
		"verdict": verdict,
		"risk":    fmt.Sprintf("%d", risk),
	}
	if digest != "" {
		detail["digest"] = digest
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    EventVerdictIssued,
		Subject: Subject(model, version),
		Actor:   "system",
		Detail:  detail,
	}
}

// DeploymentDecision builds the record for an admission decision.
func DeploymentDecision(model, version, namespace, workload string, admitted bool, why string) Record {
	t := EventDeploymentBlocked
	if admitted {
		t = EventDeploymentAdmitted
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    t,
		Subject: Subject(model, version),
		Actor:   "system",
		Detail: map[string]string{
			"namespace": namespace,
			"workload":  workload,
			"reason":    why,
		},
	}
}

// PromotionDecision builds the record for a promotion request that reached a
// terminal state.
//
// The verdict the decision was taken against is carried in the detail rather
// than left to be looked up later. A promotion is only defensible in relation
// to what was known at the time, and the ModelSecurityReport it referred to is
// mutable — by the time anyone reads this record, the verdict it names may no
// longer be the one the model has.
func PromotionDecision(model, version, environment, phase, decidedBy, verdict, why string) Record {
	t := EventModelPromoted
	if phase != "Approved" {
		t = EventPromotionRefused
	}
	actor := decidedBy
	if actor == "" {
		// Nobody decided: the security verdict did. Recording "system" here
		// rather than an empty actor keeps the distinction legible.
		actor = "system"
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    t,
		Subject: Subject(model, version),
		Actor:   actor,
		Detail: map[string]string{
			"environment": environment,
			"phase":       phase,
			"verdict":     verdict,
			"reason":      why,
		},
	}
}
