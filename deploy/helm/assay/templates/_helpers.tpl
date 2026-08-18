{{/* Chart name, overridable. */}}
{{- define "assay.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name for namespaced resources.

Cluster-scoped resources (ClusterRole, ValidatingWebhookConfiguration) keep
fixed names instead: Assay owns cluster-wide CRDs and one admission gate, so a
second release in the same cluster would fight the first regardless of naming.
One install per cluster is the supported shape.
*/}}
{{- define "assay.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "assay.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: assay-model-scanner
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels must match the existing manifests so a migration is a no-op. */}}
{{- define "assay.selectorLabels" -}}
app.kubernetes.io/name: assay-model-scanner
app.kubernetes.io/component: controller
{{- end -}}

{{- define "assay.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "assay.webhookServiceName" -}}
{{- printf "%s-webhook" (include "assay.fullname" .) -}}
{{- end -}}

{{/* Fail early on a cert mode that cannot produce a verifiable webhook. */}}
{{- define "assay.validateCertMode" -}}
{{- $m := .Values.webhook.certMode -}}
{{- if not (has $m (list "openshift" "cert-manager" "external")) -}}
{{- fail (printf "webhook.certMode must be one of openshift, cert-manager, external (got %q)" $m) -}}
{{- end -}}
{{- if and (eq $m "external") (not .Values.webhook.caBundle) -}}
{{- fail "webhook.certMode=external requires webhook.caBundle; without it the API server cannot verify the gate and, under failurePolicy Ignore, will silently skip it" -}}
{{- end -}}
{{- end -}}
