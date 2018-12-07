package step

import (
	"fmt"
	"strings"
	"time"

	"github.com/linkerd/linkerd2/controller/k8s"
	pkgK8s "github.com/linkerd/linkerd2/pkg/k8s"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	// ConfigControllerConfigMap is the configmap name where the certificates
	// will be stored.
	ConfigControllerConfigMap = "config-controller-configuration"

	// ConfigControllerSecrets is the configmap name where the provisioner
	// passwords will be stored.
	ConfigControllerSecrets = "config-controller-secrets"

	// RootCertificateKey is the key used to store the root certificate.
	RootCertificateKey = "root"

	// IntermediateCertificateKey is the key used to store the intermediate
	// certificate.
	IntermediateCertificateKey = "intermediate"

	// CAURLKey is the key used to store the CA URL.
	CAURLKey = "ca-url"

	// ProvisionerPasswordKey is the key used to store the default provisioner
	// password.
	ProvisionerPasswordKey = "provisioner-password"
)

// Configuration errors returned on the ConfigController.
var (
	ErrCaURLNotFound            = fmt.Errorf("%s key not found in configmap", CAURLKey)
	ErrRootCertNotFound         = fmt.Errorf("%s key not found in configmap", RootCertificateKey)
	ErrIntermediateCertNotFound = fmt.Errorf("%s key not found in configmap", IntermediateCertificateKey)
	ErrPasswordNotFound         = fmt.Errorf("%s key not found in secret", ProvisionerPasswordKey)
)

type ConfigController struct {
	namespace   string
	k8sAPI      *k8s.API
	syncHandler func(key string) error
	caURL       string
	password    []byte
	certs       map[string]string
	// The queue is keyed on a string. If the string doesn't contain any dots
	// then it is a namespace name and the task is to create the CA bundle
	// configmap in that namespace. Otherwise the string must be of the form
	// "$podOwner.$podKind.$podNamespace" and the task is to create the secret
	// for that pod owner.
	queue workqueue.RateLimitingInterface
}

// NewConfigController initializes a configuration controller reading configmaps
// and secrets. The configuration controller will create and update the
// configmaps and secrets used by the step renewers.
func NewConfigController(controllerNamespace string, k8sAPI *k8s.API, proxyAutoInject bool) (*ConfigController, error) {
	// Read necessary configuration
	cm, err := k8sAPI.Client.CoreV1().ConfigMaps(controllerNamespace).Get(ConfigControllerConfigMap, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get configmap [%s] from namespace [%s]", ConfigControllerConfigMap, controllerNamespace)
		return nil, err
	}

	caURL := cm.Data[CAURLKey]
	if caURL == "" {
		log.Errorf("failed to get ca-url from configmap [%s] in namespace [%s]", ConfigControllerConfigMap, controllerNamespace)
		return nil, ErrCaURLNotFound
	}
	rootCert := cm.Data[RootCertificateKey]
	if rootCert == "" {
		log.Errorf("failed to get root_ca.crt from configmap [%s] in namespace [%s]", ConfigControllerConfigMap, controllerNamespace)
		return nil, ErrRootCertNotFound
	}
	intermediateCert := cm.Data[IntermediateCertificateKey]
	if rootCert == "" {
		log.Errorf("failed to get intermediate_ca.crt from configmap [%s] in namespace [%s]", ConfigControllerConfigMap, controllerNamespace)
		return nil, ErrIntermediateCertNotFound
	}

	secret, err := k8sAPI.Client.CoreV1().Secrets(controllerNamespace).Get(ConfigControllerSecrets, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get secret [%s[ in namespace [%s]", ConfigControllerSecrets, controllerNamespace)
		return nil, err
	}

	password := secret.Data[ProvisionerPasswordKey]
	if len(password) == 0 {
		log.Errorf("failed to get password from secret [%s] in namespace [%s]", ConfigControllerSecrets, controllerNamespace)
		return nil, ErrPasswordNotFound
	}

	c := &ConfigController{
		namespace: controllerNamespace,
		k8sAPI:    k8sAPI,
		caURL:     caURL,
		password:  password,
		certs: map[string]string{
			"root-ca.pem":       rootCert,
			"trust-anchors.pem": intermediateCert,
		},
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "renewer"),
	}

	k8sAPI.Pod().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handlePodAdd,
			UpdateFunc: c.handlePodUpdate,
		},
	)

	if proxyAutoInject {
		k8sAPI.MWC().Informer().AddEventHandler(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    c.handleMWCAdd,
				UpdateFunc: c.handleMWCUpdate,
			},
		)
	}

	c.syncHandler = c.syncObject

	return c, nil
}

// Run starts the configuration controller.
func (c *ConfigController) Run(readyCh <-chan struct{}, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()

	<-readyCh

	log.Info("starting certificate controller")
	defer log.Info("shutting down certificate controller")

	go wait.Until(c.worker, time.Second, stopCh)

	<-stopCh
}

func (c *ConfigController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ConfigController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncHandler(key.(string))
	if err != nil {
		log.Errorf("error syncing object: %s", err)
		c.queue.AddRateLimited(key)
		return true
	}

	c.queue.Forget(key)
	return true
}

func (c *ConfigController) syncObject(key string) error {
	log.Debugf("syncObject(%s)", key)
	if !strings.Contains(key, ".") {
		return c.syncNamespace(key)
	}
	return c.syncSecret(key)
}

func (c *ConfigController) syncNamespace(ns string) error {
	log.Debugf("syncNamespace(%s)", ns)
	configuration := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-ca-configuration",
			Namespace: ns,
		},
		Data: map[string]string{
			"step-ca-url": c.caURL,
		},
	}

	certificates := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-linkerd-ca-bundle",
			Namespace: ns,
		},
		Data: c.certs,
	}

	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "step-provisioner-password",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"password": c.password,
		},
	}

	for _, configMap := range []*v1.ConfigMap{configuration, certificates} {
		log.Debugf("adding configmap [%s] to namespace [%s]", configMap.ObjectMeta.Name, ns)
		_, err := c.k8sAPI.Client.CoreV1().ConfigMaps(ns).Create(configMap)
		if apierrors.IsAlreadyExists(err) {
			if _, err := c.k8sAPI.Client.CoreV1().ConfigMaps(ns).Update(configMap); err != nil {
				log.Errorf("failed to update configmap [%s] to namespace [%s]", configMap.ObjectMeta.Name, ns)
				return err
			}
		}
	}

	_, err := c.k8sAPI.Client.CoreV1().Secrets(ns).Create(secret)
	if apierrors.IsAlreadyExists(err) {
		if _, err := c.k8sAPI.Client.CoreV1().Secrets(ns).Update(secret); err != nil {
			log.Errorf("failed to update secrets [%s] to namespace [%s]", secret.ObjectMeta.Name, ns)
			return nil
		}
	}

	return nil
}

func (c *ConfigController) syncSecret(key string) error {
	log.Debugf("syncSecret(%s)", key)
	parts := strings.Split(key, ".")
	if len(parts) != 3 {
		log.Errorf("Failed to parse secret sync request %s", key)
		return nil // TODO
	}
	identity := pkgK8s.TLSIdentity{
		Name:                parts[0],
		Kind:                parts[1],
		Namespace:           parts[2],
		ControllerNamespace: c.namespace,
	}

	dnsName := identity.ToDNSName()
	secretName := identity.ToSecretName()
	log.Debugf("no secret [%s] to sync to [%s]", secretName, dnsName)
	return nil
}

func (c *ConfigController) handlePodAdd(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pkgK8s.IsMeshed(pod, c.namespace) {
		log.Debugf("enqueuing update of CA bundle configmap in %s", pod.Namespace)
		c.queue.Add(pod.Namespace)

		ownerKind, ownerName := c.k8sAPI.GetOwnerKindAndName(pod)
		item := fmt.Sprintf("%s.%s.%s", ownerName, ownerKind, pod.Namespace)
		log.Debugf("enqueuing secret write for %s", item)
		c.queue.Add(item)
	}
}

func (c *ConfigController) handlePodUpdate(oldObj, newObj interface{}) {
	c.handlePodAdd(newObj)
}

func (c *ConfigController) handleMWCAdd(obj interface{}) {
	mwc := obj.(*v1beta1.MutatingWebhookConfiguration)
	log.Debugf("enqueuing secret write for mutating webhook configuration %q", mwc.ObjectMeta.Name)
	for _, webhook := range mwc.Webhooks {
		if mwc.Name == pkgK8s.ProxyInjectorWebhookConfig {
			c.queue.Add(fmt.Sprintf("%s.%s.%s", webhook.ClientConfig.Service.Name, pkgK8s.Service, webhook.ClientConfig.Service.Namespace))
		}
	}
}

func (c *ConfigController) handleMWCUpdate(oldObj, newObj interface{}) {
	c.handleMWCAdd(newObj)
}
