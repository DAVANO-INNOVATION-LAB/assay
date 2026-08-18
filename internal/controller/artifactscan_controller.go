package controller

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/JUMP1ST/assay/api/v1alpha1"
	"github.com/JUMP1ST/assay/internal/policy"
	"github.com/JUMP1ST/assay/internal/scanners"
)

// ArtifactScanReconciler drives one ArtifactScan through fetch, scan, and
// verdict. It owns the scan Jobs and the resulting ModelSecurityReport.
type ArtifactScanReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	JobConfig JobConfig
}

// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscanpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactexceptions,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the ArtifactScan state machine.
func (r *ArtifactScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var scan securityv1alpha1.ArtifactScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !scan.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if scan.Status.Phase == "" {
		scan.Status.Phase = "Pending"
		now := metav1.Now()
		scan.Status.StartTime = &now
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if scan.Status.Phase == "Completed" || scan.Status.Phase == "Failed" {
		return ctrl.Result{}, nil
	}

	pol, err := r.loadPolicy(ctx, &scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	wanted, err := resolveScanners(&scan, pol)
	if err != nil {
		return r.fail(ctx, &scan, fmt.Sprintf("cannot resolve scanner set: %v", err))
	}
	if len(wanted) == 0 {
		return r.fail(ctx, &scan, "policy selected no scanners")
	}

	// Ensure a Job exists for every selected scanner.
	for _, name := range wanted {
		if err := r.ensureScanJob(ctx, &scan, pol, name); err != nil {
			return ctrl.Result{}, err
		}
	}

	if scan.Status.Phase == "Pending" {
		scan.Status.Phase = "Scanning"
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
	}

	results, pending, err := r.collectResults(ctx, &scan, wanted)
	if err != nil {
		return ctrl.Result{}, err
	}

	scan.Status.Results = results
	if pending > 0 {
		logger.V(1).Info("waiting on scanners", "pending", pending, "scan", scan.Name)
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	exceptions, err := r.loadExceptions(ctx, &scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	eval := policy.Evaluate(results, scan.Spec.Artifact, pol, exceptions, time.Now())

	now := metav1.Now()
	scan.Status.Phase = "Completed"
	scan.Status.CompletionTime = &now
	scan.Status.RiskScore = &eval.RiskScore
	scan.Status.Verdict = eval.Verdict
	scan.Status.Message = summarize(eval)
	setCondition(&scan.Status.Conditions, metav1.Condition{
		Type:    "Complete",
		Status:  metav1.ConditionTrue,
		Reason:  "ScanFinished",
		Message: scan.Status.Message,
	})
	if err := r.Status().Update(ctx, &scan); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.upsertModelSecurityReport(ctx, &scan, eval); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("scan completed",
		"scan", scan.Name, "verdict", eval.Verdict, "risk", eval.RiskScore,
		"violations", len(eval.Violations))
	return ctrl.Result{}, nil
}

func (r *ArtifactScanReconciler) loadPolicy(ctx context.Context, scan *securityv1alpha1.ArtifactScan) (*securityv1alpha1.ArtifactScanPolicy, error) {
	if scan.Spec.PolicyRef == "" {
		return nil, nil
	}
	var pol securityv1alpha1.ArtifactScanPolicy
	err := r.Get(ctx, client.ObjectKey{Name: scan.Spec.PolicyRef, Namespace: scan.Namespace}, &pol)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load policy %q: %w", scan.Spec.PolicyRef, err)
	}
	return &pol, nil
}

func (r *ArtifactScanReconciler) loadExceptions(ctx context.Context, scan *securityv1alpha1.ArtifactScan) ([]securityv1alpha1.ArtifactException, error) {
	var list securityv1alpha1.ArtifactExceptionList
	if err := r.List(ctx, &list, client.InNamespace(scan.Namespace)); err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	var matching []securityv1alpha1.ArtifactException
	for _, ex := range list.Items {
		if ex.Spec.ModelName == scan.Spec.ModelName && ex.Spec.ModelVersion == scan.Spec.ModelVersion {
			matching = append(matching, ex)
		}
	}
	return matching, nil
}

// resolveScanners picks the scanner set: an explicit list on the scan wins,
// then the policy's enabled scanners, then the catalog defaults.
func resolveScanners(scan *securityv1alpha1.ArtifactScan, pol *securityv1alpha1.ArtifactScanPolicy) ([]string, error) {
	var names []string
	switch {
	case len(scan.Spec.Scanners) > 0:
		names = scan.Spec.Scanners
	case pol != nil && len(pol.Spec.Scanners) > 0:
		for _, s := range pol.Spec.Scanners {
			if s.Enabled != nil && !*s.Enabled {
				continue
			}
			names = append(names, s.Name)
		}
	default:
		names = scanners.Defaults()
	}

	for _, name := range names {
		if _, err := scanners.Get(name); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func (r *ArtifactScanReconciler) ensureScanJob(ctx context.Context, scan *securityv1alpha1.ArtifactScan, pol *securityv1alpha1.ArtifactScanPolicy, name string) error {
	def, err := scanners.Get(name)
	if err != nil {
		return err
	}

	jobName := scanJobName(scan.Name, name)
	var existing batchv1.Job
	err = r.Get(ctx, client.ObjectKey{Name: jobName, Namespace: scan.Namespace}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("check scan job %s: %w", jobName, err)
	}

	job, err := buildScanJob(scan, def, findScannerSpec(pol, name), r.JobConfig)
	if err != nil {
		return fmt.Errorf("build scan job for %s: %w", name, err)
	}
	if err := controllerutil.SetControllerReference(scan, job, r.Scheme); err != nil {
		return fmt.Errorf("set owner on scan job: %w", err)
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create scan job %s: %w", jobName, err)
	}
	return nil
}

func findScannerSpec(pol *securityv1alpha1.ArtifactScanPolicy, name string) *securityv1alpha1.ScannerSpec {
	if pol == nil {
		return nil
	}
	for i := range pol.Spec.Scanners {
		if pol.Spec.Scanners[i].Name == name {
			return &pol.Spec.Scanners[i]
		}
	}
	return nil
}

// collectResults reads the ArtifactScanReport each publish step wrote, and
// falls back to Job status for scanners that produced no report.
func (r *ArtifactScanReconciler) collectResults(ctx context.Context, scan *securityv1alpha1.ArtifactScan, wanted []string) ([]securityv1alpha1.ScannerResult, int, error) {
	var reports securityv1alpha1.ArtifactScanReportList
	if err := r.List(ctx, &reports, client.InNamespace(scan.Namespace), client.MatchingLabels{LabelScan: scan.Name}); err != nil {
		return nil, 0, fmt.Errorf("list scan reports: %w", err)
	}
	byScanner := map[string]securityv1alpha1.ScannerResult{}
	for _, report := range reports.Items {
		summary := report.Summary
		summary.Scanner = report.Scanner
		summary.ReportRef = report.Name
		byScanner[report.Scanner] = summary
	}

	var (
		results []securityv1alpha1.ScannerResult
		pending int
	)
	for _, name := range wanted {
		if result, ok := byScanner[name]; ok {
			results = append(results, result)
			continue
		}

		// No report yet: derive interim status from the Job.
		result := securityv1alpha1.ScannerResult{Scanner: name, Status: "Pending"}
		var job batchv1.Job
		err := r.Get(ctx, client.ObjectKey{Name: scanJobName(scan.Name, name), Namespace: scan.Namespace}, &job)
		switch {
		case apierrors.IsNotFound(err):
			result.Status = "Pending"
		case err != nil:
			return nil, 0, fmt.Errorf("get scan job for %s: %w", name, err)
		case job.Status.Failed > 0:
			result.Status = "Error"
			result.Message = "scan job failed; see job logs"
		case job.Status.Active > 0:
			result.Status = "Running"
		case job.Status.Succeeded > 0:
			// The job finished but the report has not landed yet.
			result.Status = "Running"
			result.Message = "waiting for scan report"
		}

		if result.Status != "Error" {
			pending++
		}
		results = append(results, result)
	}
	return results, pending, nil
}

func (r *ArtifactScanReconciler) upsertModelSecurityReport(ctx context.Context, scan *securityv1alpha1.ArtifactScan, eval policy.Evaluation) error {
	if scan.Spec.ModelName == "" || scan.Spec.ModelVersion == "" {
		return nil
	}

	name := modelReportName(scan.Spec.ModelName, scan.Spec.ModelVersion)
	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: scan.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, report, func() error {
		report.Spec = securityv1alpha1.ModelSecurityReportSpec{
			ModelName:    scan.Spec.ModelName,
			ModelVersion: scan.Spec.ModelVersion,
			Artifact:     scan.Spec.Artifact,
			ScanRef:      scan.Name,
		}
		if report.Labels == nil {
			report.Labels = map[string]string{}
		}
		report.Labels[LabelManagedBy] = ManagerName
		report.Labels["security.davano.io/model"] = sanitizeLabel(scan.Spec.ModelName)
		return nil
	})
	if err != nil {
		return fmt.Errorf("upsert model security report: %w", err)
	}

	now := metav1.Now()
	report.Status.Verdict = eval.Verdict
	report.Status.RiskScore = eval.RiskScore
	report.Status.Malware = eval.MalwareStatus
	report.Status.Secrets = eval.SecretsStatus
	report.Status.CVEs = eval.CVEs
	report.Status.SignatureVerified = eval.SignatureVerified
	report.Status.Scanners = scan.Status.Results
	report.Status.LastScanTime = &now
	report.Status.SBOMRef = sbomRef(scan.Status.Results)

	condition := metav1.Condition{
		Type:    "Approved",
		Status:  metav1.ConditionFalse,
		Reason:  "PolicyViolation",
		Message: summarize(eval),
	}
	if eval.Verdict == securityv1alpha1.VerdictApproved {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "PolicyPassed"
	}
	setCondition(&report.Status.Conditions, condition)

	if err := r.Status().Update(ctx, report); err != nil {
		return fmt.Errorf("update model security report status: %w", err)
	}
	return nil
}

func (r *ArtifactScanReconciler) fail(ctx context.Context, scan *securityv1alpha1.ArtifactScan, message string) (ctrl.Result, error) {
	now := metav1.Now()
	scan.Status.Phase = "Failed"
	scan.Status.Message = message
	scan.Status.CompletionTime = &now
	scan.Status.Verdict = securityv1alpha1.VerdictReviewRequired
	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func sbomRef(results []securityv1alpha1.ScannerResult) string {
	for _, r := range results {
		if def, err := scanners.Get(r.Scanner); err == nil && def.Category == scanners.CategorySBOM {
			return r.ReportRef
		}
	}
	return ""
}

func summarize(eval policy.Evaluation) string {
	if len(eval.Violations) == 0 {
		if len(eval.Waived) > 0 {
			return fmt.Sprintf("passed policy with %d waived violation(s)", len(eval.Waived))
		}
		return "passed all policy rules"
	}
	return fmt.Sprintf("%d policy violation(s): %s", len(eval.Violations), eval.Violations[0].String())
}

// SetupWithManager wires the reconciler into the manager.
func (r *ArtifactScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ArtifactScan{}).
		Owns(&batchv1.Job{}).
		Watches(
			&securityv1alpha1.ArtifactScanReport{},
			handler.EnqueueRequestsFromMapFunc(mapReportToScan),
		).
		Named("artifactscan").
		Complete(r)
}

// mapReportToScan requeues the owning scan when a scanner publishes results.
func mapReportToScan(_ context.Context, obj client.Object) []reconcile.Request {
	report, ok := obj.(*securityv1alpha1.ArtifactScanReport)
	if !ok || report.ScanRef == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Name: report.ScanRef, Namespace: report.Namespace},
	}}
}
