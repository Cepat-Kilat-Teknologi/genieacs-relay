{{/*
_helpers.tpl - Template helper functions
Functions that can be called from other templates with: {{ include "function-name" . }}
*/}}

{{/*
Chart name
*/}}
{{- define "genieacs-relay.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fullname: release-name + chart-name
Example: my-release-genieacs-relay
*/}}
{{- define "genieacs-relay.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label: chart-name-version
*/}}
{{- define "genieacs-relay.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels - used in all resources
*/}}
{{- define "genieacs-relay.labels" -}}
helm.sh/chart: {{ include "genieacs-relay.chart" . }}
{{ include "genieacs-relay.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels - used for pod matching
*/}}
{{- define "genieacs-relay.selectorLabels" -}}
app.kubernetes.io/name: {{ include "genieacs-relay.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "genieacs-relay.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "genieacs-relay.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image name with tag
*/}}
{{- define "genieacs-relay.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Secret name for NBI auth
*/}}
{{- define "genieacs-relay.nbiSecretName" -}}
{{- if .Values.config.nbiAuth.existingSecret }}
{{- .Values.config.nbiAuth.existingSecret }}
{{- else }}
{{- printf "%s-nbi" (include "genieacs-relay.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for middleware auth
*/}}
{{- define "genieacs-relay.authSecretName" -}}
{{- if .Values.config.middlewareAuth.existingSecret }}
{{- .Values.config.middlewareAuth.existingSecret }}
{{- else }}
{{- printf "%s-auth" (include "genieacs-relay.fullname" .) }}
{{- end }}
{{- end }}
