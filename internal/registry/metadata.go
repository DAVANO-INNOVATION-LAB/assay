package registry

import (
	"fmt"
	"time"

	securityv1alpha1 "github.com/zeus-security/zeus-operator/api/v1alpha1"
)

// Property keys Zeus writes back into the Model Registry. They are namespaced
// so they never collide with user-defined properties.
const (
	PropVerdict      = "zeus.security/verdict"
	PropRiskScore    = "zeus.security/risk-score"
	PropMalware      = "zeus.security/malware"
	PropSecrets      = "zeus.security/secrets"
	PropCVECritical  = "zeus.security/cve-critical"
	PropCVEHigh      = "zeus.security/cve-high"
	PropSigned       = "zeus.security/signature-verified"
	PropLastScan     = "zeus.security/last-scan"
	PropReportRef    = "zeus.security/report"
	PropScannerCount = "zeus.security/scanners-run"
)

// SummaryProperties renders a ModelSecurityReport as registry custom
// properties. Detailed findings deliberately stay in-cluster.
func SummaryProperties(report *securityv1alpha1.ModelSecurityReport) map[string]MetadataValue {
	status := report.Status
	props := map[string]MetadataValue{
		PropVerdict:      StringProperty(orUnknown(status.Verdict)),
		PropRiskScore:    IntProperty(int64(status.RiskScore)),
		PropMalware:      StringProperty(orUnknown(status.Malware)),
		PropSecrets:      StringProperty(orUnknown(status.Secrets)),
		PropCVECritical:  IntProperty(int64(status.CVEs.Critical)),
		PropCVEHigh:      IntProperty(int64(status.CVEs.High)),
		PropSigned:       BoolProperty(status.SignatureVerified),
		PropScannerCount: IntProperty(int64(len(status.Scanners))),
		PropReportRef:    StringProperty(fmt.Sprintf("%s/%s", report.Namespace, report.Name)),
	}
	if status.LastScanTime != nil {
		props[PropLastScan] = StringProperty(status.LastScanTime.UTC().Format(time.RFC3339))
	}
	return props
}

func orUnknown(v string) string {
	if v == "" {
		return securityv1alpha1.VerdictUnknown
	}
	return v
}
