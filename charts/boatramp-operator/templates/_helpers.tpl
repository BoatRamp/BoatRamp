{{/* The release-scoped name (kept short + DNS-safe). */}}
{{- define "boatramp-operator.name" -}}
boatramp-operator
{{- end -}}

{{/* Standard labels applied to every rendered resource. */}}
{{- define "boatramp-operator.labels" -}}
app.kubernetes.io/name: boatramp-operator
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: boatramp
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels (stable across upgrades). */}}
{{- define "boatramp-operator.selectorLabels" -}}
app.kubernetes.io/name: boatramp-operator
app.kubernetes.io/managed-by: boatramp
{{- end -}}

{{/* The operator image ref (tag defaults to the chart appVersion). */}}
{{- define "boatramp-operator.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ printf "%s:%s" .Values.image.repository $tag }}
{{- end -}}
