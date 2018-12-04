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

// stepCAConfig contains the fields used in the Smallstep CA template.
type stepCAConfig struct {
	Namespace           string
	Image               string
	ConfigFile          string
	PasswordFile        string
	CreatedByAnnotation string
	CliVersion          string
	ImagePullPolicy     string
	EnableHA            bool
}

// stepConfigOptions represents the CLI flags used to use the Smallstep
// certificates.
type stepConfigOptions struct {
	*stepCAConfig
	stepNamespace   string
	stepConfigPath  string
	stepPKIPath     string
	stepPKIPassword string
}

func newStepConfigOptions() *stepConfigOptions {
	return &stepConfigOptions{
		stepCAConfig: &stepCAConfig{
			Namespace:           "step",
			Image:               "smallstep/step-ca:0.8.1-rc.2",
			ConfigFile:          "/home/step/.step/config/ca.json",
			PasswordFile:        "/home/step/secrets/password",
			CreatedByAnnotation: k8s.CreatedByAnnotation,
			CliVersion:          k8s.CreatedByAnnotationValue(),
		},
	}
}

func addStepConfigFlags(cmd *cobra.Command, options *stepConfigOptions) {
	cmd.PersistentFlags().StringVar(&options.stepConfigPath, "step-config", options.stepConfigPath, "Experimental: Path to the step CA configuration file")
	cmd.PersistentFlags().StringVar(&options.stepPKIPath, "step-pki", options.stepPKIPath, "Experimental: Path to the step PKI configuration files")
	cmd.PersistentFlags().StringVar(&options.stepPKIPassword, "step-password-file", options.stepPKIPassword, "Experimental: Path to the file to decrypt to PKI intermediate certificate")
}

func (options *stepConfigOptions) validate() error {
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
	config := options.stepConfigOptions
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
			return fmt.Errorf("error marshaling namespace: %v", err)
		}
		if _, err := out.Write(b); err != nil {
			return fmt.Errorf("error writing namespace: %v", err)
		}
		out.Write([]byte("---\n"))
	}

	// Write Step CA Pod
	stepCATemplate, err := template.New("linkerd").Parse(install.StepCATemplate)
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}
	err = stepCATemplate.Execute(out, config.stepCAConfig)
	if err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}
