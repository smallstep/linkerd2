package step

type TemplateData struct {
	Namespace                string
	ConfigMapName            string
	ControllerComponentLabel string
	ControllerImage          string
	ControllerLogLevel       string
	ImagePullPolicy          string
	CreatedByAnnotation      string
	CliVersion               string
	SingleNamespace          bool
	ProxyAutoInjectEnabled   bool
	EnableTLS                bool
	EnableHA                 bool
}

const Template = `
### Step Controller Service Account ###
---
kind: ServiceAccount
apiVersion: v1
metadata:
  name: step-controller
  namespace: {{.Namespace}}

### Step Controller RBAC ###
---
kind: {{if not .SingleNamespace}}Cluster{{end}}Role
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: step-{{.Namespace}}-controller
  {{- if .SingleNamespace}}
  namespace: {{.Namespace}}
  {{- end}}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["create", "get", "update"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list", "get", "watch"]
- apiGroups: ["extensions", "apps"]
  resources: ["replicasets"]
  verbs: ["list", "get", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "get", "update"]
{{- if and .EnableTLS .ProxyAutoInjectEnabled }}
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations"]
  verbs: ["list", "get", "watch"]
{{- end }}

---
kind: {{if not .SingleNamespace}}Cluster{{end}}RoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: step-{{.Namespace}}-controller
  {{- if .SingleNamespace}}
  namespace: {{.Namespace}}
  {{- end}}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: {{if not .SingleNamespace}}Cluster{{end}}Role
  name: step-{{.Namespace}}-controller
subjects:
- kind: ServiceAccount
  name: step-controller
  namespace: {{.Namespace}}

### Step Controller ###
---
kind: Deployment
apiVersion: extensions/v1beta1
metadata:
  name: step-controller
  namespace: {{.Namespace}}
  labels:
    {{.ControllerComponentLabel}}: step-controller
  annotations:
    {{.CreatedByAnnotation}}: {{.CliVersion}}
spec:
  replicas: 1
  template:
    metadata:
      labels:
        {{.ControllerComponentLabel}}: step-controller
      annotations:
        {{.CreatedByAnnotation}}: {{.CliVersion}}
    spec:
      serviceAccount: step-controller
      containers:
      - name: step-controller
        ports:
        - name: admin-http
          containerPort: 9997
        image: {{.ControllerImage}}
        imagePullPolicy: {{.ImagePullPolicy}}
        args:
        - "step"
        - "-controller-namespace={{.Namespace}}"
        - "-single-namespace={{.SingleNamespace}}"
        {{- if and .EnableTLS .ProxyAutoInjectEnabled }}
        - "-proxy-auto-inject={{ .ProxyAutoInjectEnabled }}"
        {{- end }}
        - "-log-level={{.ControllerLogLevel}}"
        livenessProbe:
          httpGet:
            path: /ping
            port: 9997
          initialDelaySeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 9997
          failureThreshold: 7
        {{- if .EnableHA }}
        resources:
          requests:
            cpu: 20m
            memory: 50Mi
        {{- end }}
`
