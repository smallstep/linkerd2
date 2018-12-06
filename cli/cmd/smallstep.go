package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"text/template"
	"unicode"

	"github.com/ghodss/yaml"
	"github.com/linkerd/linkerd2/cli/install"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/spf13/cobra"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// stepInstallConfig contains the fields used in the Smallstep CA template.
type stepInstallConfig struct {
	Namespace           string
	Image               string
	ConfigFile          string
	PasswordFile        string
	CreatedByAnnotation string
	CliVersion          string
	ImagePullPolicy     string
	EnableHA            bool
}

// stepInstallOptions represents the CLI flags used on install to use step
// certificates.
type stepInstallOptions struct {
	*stepInstallConfig
	stepNamespace   string
	stepConfigPath  string
	stepPKIPath     string
	stepPKIPassword string
}

func newStepInstallOptions() *stepInstallOptions {
	return &stepInstallOptions{
		stepInstallConfig: &stepInstallConfig{
			Namespace:           "step",
			Image:               "smallstep/step-ca:0.8.1-rc.2",
			ConfigFile:          "/home/step/.step/config/ca.json",
			PasswordFile:        "/home/step/secrets/password",
			CreatedByAnnotation: k8s.CreatedByAnnotation,
			CliVersion:          k8s.CreatedByAnnotationValue(),
		},
	}
}

func addStepInstallFlags(cmd *cobra.Command, options *stepInstallOptions) {
	cmd.PersistentFlags().StringVar(&options.stepConfigPath, "step-config", options.stepConfigPath, "Experimental: Path to the step CA configuration file")
	cmd.PersistentFlags().StringVar(&options.stepPKIPath, "step-pki", options.stepPKIPath, "Experimental: Path to the step PKI configuration files")
	cmd.PersistentFlags().StringVar(&options.stepPKIPassword, "step-password-file", options.stepPKIPassword, "Experimental: Path to the file to decrypt to PKI intermediate certificate")
}

func (options *stepInstallOptions) validate() error {
	if options.stepConfigPath == "" {
		return fmt.Errorf("--step-config must be provided with --tls=step")
	}
	if options.stepPKIPath == "" {
		return fmt.Errorf("--step-pki must be provided with --tls=step")
	}
	if options.stepPKIPassword == "" {
		return fmt.Errorf("--step-password-file must be provided with --tls=step")
	}
	return nil
}

func injectStepCAConfiguration(out io.Writer, options *installOptions) error {
	config := options.stepInstallOptions
	config.ImagePullPolicy = options.imagePullPolicy
	config.EnableHA = options.highAvailability

	caConfigData, err := ioutil.ReadFile(config.stepConfigPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", config.stepConfigPath, err)
	}

	files, err := ioutil.ReadDir(config.stepPKIPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", config.stepPKIPath, err)
	}

	caCertificatesData := make(map[string]string)
	for _, file := range files {
		if !file.IsDir() {
			path := filepath.Join(config.stepPKIPath, file.Name())
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("error reading %s: %v", path, err)
			}
			caCertificatesData[file.Name()] = string(data)
		}
	}

	password, err := ioutil.ReadFile(config.stepPKIPassword)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", config.stepPKIPassword, err)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)

	// Create namespace, configMaps and secrets
	namespace := v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: config.Namespace,
		},
	}

	caConfig := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-config",
			Namespace: config.Namespace,
		},
		Data: map[string]string{
			"ca.json": string(caConfigData),
		},
	}

	caCertificates := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-certificates",
			Namespace: config.Namespace,
		},
		Data: caCertificatesData,
	}

	caCertificatePassword := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-certificate-password",
			Namespace: config.Namespace,
		},
		Data: map[string][]byte{
			"password": password,
		},
	}

	// Write namespace, configMaps and secrets
	toMarshal := []interface{}{
		namespace, caConfig, caCertificates, caCertificatePassword,
	}
	for _, o := range toMarshal {
		b, err := yaml.Marshal(o)
		if err != nil {
			return fmt.Errorf("error marshaling yaml: %v", err)
		}
		if _, err := out.Write(b); err != nil {
			return fmt.Errorf("error writing yaml: %v", err)
		}
		out.Write([]byte("---\n"))
	}

	// Write Step CA Pod
	stepCATemplate, err := template.New("linkerd").Parse(install.StepCATemplate)
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}
	err = stepCATemplate.Execute(out, config.stepInstallConfig)
	if err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}

func getStepRenewerTrustAnchorsVolume() v1.Volume {
	return v1.Volume{
		Name: "step-linkerd-trust-anchors",
		VolumeSource: v1.VolumeSource{
			ConfigMap: &v1.ConfigMapVolumeSource{
				LocalObjectReference: v1.LocalObjectReference{Name: "step-linkerd-ca-bundle"},
			},
		},
	}
}

func getStepRenewerSecretsVolume() v1.Volume {
	return v1.Volume{
		Name: "step-linkerd-secrets",
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
}

func injectStepRenewerSidecar(t *v1.PodSpec, identity k8s.TLSIdentity, options *injectOptions) {
	base := "/var/linkerd-io"
	configMapBase := base + "/trust-anchors"
	secretBase := base + "/identity"

	sidecar := v1.Container{
		Name:                     "step-renewer",
		Image:                    "smallstep/step-renewer:latest",
		TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
		Env: []v1.EnvVar{
			{Name: "COMMON_NAME", Value: identity.ToDNSName()},
			{Name: "TLS_CERTIFICATE", Value: secretBase + "/" + k8s.TLSCertFileName},
			{Name: "TLS_PRIVATE_KEY", Value: secretBase + "/" + k8s.TLSPrivateKeyFileName},
			{Name: PodNamespaceEnvVarName, ValueFrom: &v1.EnvVarSource{FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
			{Name: "STEP_ROOT", Value: configMapBase + "/root-ca.pem"},
			{Name: "STEP_PASSWORD_FILE", Value: "/var/local/step/secrets/password"},
			{Name: "STEP_RENEW_CRONTAB", Value: ""},
			{Name: "STEP_CA_URL", ValueFrom: &v1.EnvVarSource{
				ConfigMapKeyRef: &v1.ConfigMapKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "step-ca-configuration",
					},
					Key: "step-ca-url",
				},
			}},
		},
	}

	configMapVolume := getStepRenewerTrustAnchorsVolume()
	secretVolume := getStepRenewerSecretsVolume()
	stepProvisionerPassword := v1.Volume{
		Name: "step-provisioner-password",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: "step-provisioner-password",
			},
		},
	}
	sidecar.VolumeMounts = []v1.VolumeMount{
		{Name: configMapVolume.Name, MountPath: configMapBase, ReadOnly: false},
		{Name: secretVolume.Name, MountPath: secretBase, ReadOnly: false},
		{Name: stepProvisionerPassword.Name, MountPath: "/var/local/step/secrets", ReadOnly: true},
	}

	t.Containers = append(t.Containers, sidecar)
	t.Volumes = append(t.Volumes, stepProvisionerPassword)
}
