{{- define "sentinel-cortex.name" -}}
sentinel-cortex
{{- end }}
{{- define "sentinel-cortex.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "sentinel-cortex.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "sentinel-cortex.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinel-cortex.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}
