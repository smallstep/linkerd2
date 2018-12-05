package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"unicode"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type provisionOptions struct {
	caURL        string
	pkiPath      string
	passwordFile string
}

func newProvisionOptions() *provisionOptions {
	return &provisionOptions{}
}

func (options *provisionOptions) validate() error {
	if options.caURL == "" {
		return fmt.Errorf("--step-ca-url must be provided with --tls=step")
	}
	if options.pkiPath == "" {
		return fmt.Errorf("--step-pki must be provided with --tls=step")
	}
	if options.passwordFile == "" {
		return fmt.Errorf("--step-password-file must be provided with --tls=step")
	}

	u, err := url.Parse(options.caURL)
	if err != nil {
		return fmt.Errorf("error parsing %s: %v", options.caURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s is not a valid URL for --step-ca-url", options.caURL)
	}

	return nil
}

func newCmdProvision() *cobra.Command {
	options := newProvisionOptions()
	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Provision the step configuration in a namespace",
		Long: `Provision the step configuration in a namespace.

The provision command will create the configmaps and secrets to be able to use
the the step CA.`,
		Example: `  # Provision the namespace "test"
linkerd provision --step-pki certs/ \
  --step-ca-url https://step.ca:9000 \
  --step-password-file path/to/password.txt \
  test`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.validate(); err != nil {
				return err
			}

			return provisionNamespace(os.Stdout, options, args[0])
		},
	}

	cmd.PersistentFlags().StringVar(&options.caURL, "step-ca-url", options.caURL, "Experimental: URL of the step CA endpoint (i.e. \"https://step.ca:9000\"")
	cmd.PersistentFlags().StringVar(&options.pkiPath, "step-pki", options.pkiPath, "Experimental: Path to a directory with the step root and intermediate certificates")
	cmd.PersistentFlags().StringVar(&options.passwordFile, "step-password-file", options.passwordFile, "Experimental: Path to the file to decrypt the provisioner key")
	return cmd
}

func provisionNamespace(out io.Writer, options *provisionOptions, namespace string) error {
	certs := make(map[string]string)
	certsMap := map[string]string{
		"trust-anchors.pem": "intermediate_ca.crt",
		"root-ca.pem":       "root_ca.crt",
	}
	for key, name := range certsMap {
		path := filepath.Join(options.pkiPath, name)
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error reading %s: %v", path, err)
		}
		certs[key] = string(data)
	}

	password, err := ioutil.ReadFile(options.passwordFile)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", options.passwordFile, err)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)

	// Create namespace, configMaps and secret
	ns := v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}

	caConfig := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-ca-configuration",
			Namespace: namespace,
		},
		Data: map[string]string{
			"step-ca-url": options.caURL,
		},
	}

	certificates := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-linkerd-ca-bundle",
			Namespace: namespace,
		},
		Data: certs,
	}

	provisionPassword := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-provisioner-password",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"password": password,
		},
	}

	// Write namespace, configMaps and secrets
	toMarshal := []interface{}{
		ns, caConfig, certificates, provisionPassword,
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

	return nil
}
