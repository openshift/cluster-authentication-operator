package externaloidc

import (
	"context"
	"encoding/json"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/externaloidc/generation/kubeapiserver"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/externaloidc/generation/oauthapiserver"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

const (
	configNamespace        = "openshift-config"
	managedNamespace       = "openshift-config-managed"
	targetAuthConfigCMName = "auth-config"
	authConfigDataKey      = "auth-config.json"
)

type authConfigGenerator interface {
	GenerateAuthenticationConfiguration(*configv1.Authentication) (runtime.Object, error)
}

type externalOIDCController struct {
	name                string
	eventName           string
	authLister          configv1listers.AuthenticationLister
	configMapLister     corev1listers.ConfigMapLister
	configMaps          corev1client.ConfigMapsGetter
	authConfigGenerator authConfigGenerator
}

func NewExternalOIDCController(
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	configMaps corev1client.ConfigMapsGetter,
	recorder events.Recorder,
	featureGates featuregates.FeatureGate,
) factory.Controller {
	var authCfgGenerator authConfigGenerator

	authCfgGenerator = kubeapiserver.NewAuthenticationConfigurationGenerator(kubeInformersForNamespaces.ConfigMapLister(), featureGates)

	if featureGates.Enabled(features.FeatureGateExternalOIDCExternalClaimsSourcing) {
		authCfgGenerator = oauthapiserver.NewAuthenticationConfigurationGenerator(kubeInformersForNamespaces.ConfigMapLister(), kubeInformersForNamespaces.SecretLister(), featureGates)
	}

	c := &externalOIDCController{
		name:      "ExternalOIDCController",
		eventName: "external-oidc-controller",

		authLister:          configInformer.Config().V1().Authentications().Lister(),
		configMapLister:     kubeInformersForNamespaces.ConfigMapLister(),
		configMaps:          configMaps,
		authConfigGenerator: authCfgGenerator,
	}

	return factory.New().WithInformers(
		// track openshift-config for changes to the provider's CA bundle
		kubeInformersForNamespaces.InformersFor(configNamespace).Core().V1().ConfigMaps().Informer(),
		// track auth resource
		configInformer.Config().V1().Authentications().Informer(),
	).WithFilteredEventsInformers(
		// track openshift-config-managed/auth-config cm in case it gets changed externally
		factory.NamesFilter(targetAuthConfigCMName),
		kubeInformersForNamespaces.InformersFor(managedNamespace).Core().V1().ConfigMaps().Informer(),
	).WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController(c.name, recorder.WithComponentSuffix(c.eventName))
}

func (c *externalOIDCController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	auth, err := c.authLister.Get("cluster")
	if err != nil {
		return fmt.Errorf("could not get authentication/cluster: %v", err)
	}

	if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		// auth type is "IntegratedOAuth", "" or "None"; delete structured auth configmap if it exists
		return c.deleteAuthConfig(ctx, syncCtx)
	}

	authConfig, err := c.authConfigGenerator.GenerateAuthenticationConfiguration(auth)
	if err != nil {
		return err
	}

	expectedApplyConfig, err := getExpectedApplyConfig(authConfig)
	if err != nil {
		return err
	}

	existingApplyConfig, err := c.getExistingApplyConfig()
	if err != nil {
		return err
	}

	if existingApplyConfig != nil && equality.Semantic.DeepEqual(existingApplyConfig.Data, expectedApplyConfig.Data) {
		return nil
	}

	if _, err := c.configMaps.ConfigMaps(managedNamespace).Apply(ctx, expectedApplyConfig, metav1.ApplyOptions{FieldManager: c.name, Force: true}); err != nil {
		return fmt.Errorf("could not apply changes to auth configmap %s/%s: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	syncCtx.Recorder().Eventf(c.eventName, "Synced auth configmap %s/%s", managedNamespace, targetAuthConfigCMName)

	return nil
}

// deleteAuthConfig checks if the auth config ConfigMap exists in the managed namespace, and deletes it
// if it does; it returns an error if it encounters one.
func (c *externalOIDCController) deleteAuthConfig(ctx context.Context, syncCtx factory.SyncContext) error {
	if _, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName); apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if err := c.configMaps.ConfigMaps(managedNamespace).Delete(ctx, targetAuthConfigCMName, metav1.DeleteOptions{}); err == nil {
		syncCtx.Recorder().Eventf(c.eventName, "Removed auth configmap %s/%s", managedNamespace, targetAuthConfigCMName)
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not delete existing configmap %s/%s: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	return nil
}

// getExpectedApplyConfig serializes the input authConfig into JSON and creates an apply configuration
// for a configmap with the serialized authConfig in the right key.
func getExpectedApplyConfig(authConfig any) (*corev1ac.ConfigMapApplyConfiguration, error) {
	authConfigBytes, err := json.Marshal(authConfig)
	if err != nil {
		return nil, fmt.Errorf("could not marshal auth config into JSON: %v", err)
	}

	expectedCMApplyConfig := corev1ac.ConfigMap(targetAuthConfigCMName, managedNamespace).
		WithData(map[string]string{
			authConfigDataKey: string(authConfigBytes),
		})

	return expectedCMApplyConfig, nil
}

// getExistingApplyConfig checks if an authConfig configmap already exists, and returns an apply configuration
// that represents it if it does; it returns nil otherwise.
func (c *externalOIDCController) getExistingApplyConfig() (*corev1ac.ConfigMapApplyConfiguration, error) {
	existingCM, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName)
	if apierrors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("could not retrieve auth configmap %s/%s to check data before sync: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	existingCMApplyConfig, err := corev1ac.ExtractConfigMap(existingCM, c.name)
	if err != nil {
		return nil, fmt.Errorf("could not extract ConfigMap apply configuration: %v", err)
	}

	return existingCMApplyConfig, nil
}
