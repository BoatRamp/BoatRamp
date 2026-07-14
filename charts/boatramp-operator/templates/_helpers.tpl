{{/* The release-scoped name (kept short + DNS-safe). */}}
{{- define "boatramp-operator.name" -}}
boatramp-operator
{{- end -}}

{{/* Selector labels — a STABLE subset used for `spec.selector` (immutable after
     create) and echoed into pod templates. Must never carry churny labels like
     `helm.sh/chart` or `managed-by`. */}}
{{- define "boatramp-operator.selectorLabels" -}}
app.kubernetes.io/name: boatramp-operator
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Standard labels for every rendered resource — a SUPERSET of the selector
     labels (Kubernetes requires `spec.selector` ⊆ `template.metadata.labels`). */}}
{{- define "boatramp-operator.labels" -}}
{{ include "boatramp-operator.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: boatramp
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* The operator image ref (tag defaults to the chart appVersion). */}}
{{- define "boatramp-operator.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ printf "%s:%s" .Values.image.repository $tag }}
{{- end -}}
