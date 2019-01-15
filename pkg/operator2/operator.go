package operator2

import (
	"github.com/golang/glog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	authv1alpha1 "github.com/openshift/cluster-osin-operator/pkg/apis/authentication/v1alpha1"
	"github.com/openshift/cluster-osin-operator/pkg/boilerplate/operator"
	authopclient "github.com/openshift/cluster-osin-operator/pkg/generated/clientset/versioned/typed/authentication/v1alpha1"
	authopinformer "github.com/openshift/cluster-osin-operator/pkg/generated/informers/externalversions/authentication/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

const (
	targetName = "openshift-osin" // TODO fix

	configKey = "config.yaml"

	servingCertName     = "serving-cert"
	servingCertMount    = "/var/run/secrets/serving-cert"
	servingCertPathCert = servingCertMount + "/" + corev1.TLSCertKey
	servingCertPathKey  = servingCertMount + "/" + corev1.TLSPrivateKeyKey

	clusterCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	systemConfigPath = "/var/config/system"

	sessionKey   = "session"
	sessionMount = systemConfigPath + "/" + sessionKey
	sessionPath  = sessionMount + "/" + sessionKey

	globalConfigName = "cluster"

	machineConfigNamespace = "openshift-config-managed"
	userConfigNamespace    = "openshift-config"

	servicePort = 6443
)

type authOperator struct {
	authOperatorConfig authopclient.AuthenticationOperatorConfigInterface

	recorder events.Recorder

	route routeclient.RouteInterface

	services    corev1client.ServicesGetter
	secrets     corev1client.SecretsGetter
	configMaps  corev1client.ConfigMapsGetter
	deployments appsv1client.DeploymentsGetter

	authentication configv1client.AuthenticationInterface
	oauth          configv1client.OAuthInterface

	resourceSyncer resourcesynccontroller.ResourceSyncer
}

func NewAuthenticationOperator(
	authOpConfigInformer authopinformer.AuthenticationOperatorConfigInformer,
	authOpConfigClient authopclient.AuthenticationOperatorConfigsGetter,
	kubeInformersNamespaced informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteV1Interface,
	configInformers configinformer.SharedInformerFactory,
	configClient configclient.Interface,
	recorder events.Recorder,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
) operator.Runner {
	c := &authOperator{
		authOperatorConfig: authOpConfigClient.AuthenticationOperatorConfigs(),

		recorder: recorder,

		route: routeClient.Routes(targetName),

		services:    kubeClient.CoreV1(),
		secrets:     kubeClient.CoreV1(),
		configMaps:  kubeClient.CoreV1(),
		deployments: kubeClient.AppsV1(),

		authentication: configClient.ConfigV1().Authentications(),
		oauth:          configClient.ConfigV1().OAuths(),

		resourceSyncer: resourceSyncer,
	}

	coreInformers := kubeInformersNamespaced.Core().V1()
	configV1Informers := configInformers.Config().V1()

	authOpConfigNameFilter := operator.FilterByNames(globalConfigName)
	osinNameFilter := operator.FilterByNames(targetName)
	configNameFilter := operator.FilterByNames(globalConfigName)

	return operator.New("AuthenticationOperator2", c,
		operator.WithInformer(authOpConfigInformer, authOpConfigNameFilter),
		operator.WithInformer(routeInformer, osinNameFilter),
		operator.WithInformer(coreInformers.Services(), osinNameFilter),
		operator.WithInformer(coreInformers.Secrets(), osinNameFilter),
		// TODO need to watch config map in configNamespace
		// TODO also need to watch all secret and configmaps that may get mounted into deployment,
		// so we may need to all config maps and secrets in the openshift-config namespace
		operator.WithInformer(coreInformers.ConfigMaps(), osinNameFilter),
		operator.WithInformer(kubeInformersNamespaced.Apps().V1().Deployments(), osinNameFilter),
		operator.WithInformer(configV1Informers.Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.OAuths(), configNameFilter),
	)
}

func (c *authOperator) Key() (metav1.Object, error) {
	return c.authOperatorConfig.Get(globalConfigName, metav1.GetOptions{})
}

func (c *authOperator) Sync(obj metav1.Object) error {
	authConfig := obj.(*authv1alpha1.AuthenticationOperatorConfig)

	if authConfig.Spec.ManagementState != operatorv1.Managed {
		return nil // TODO do something better for all states
	}

	if err := c.handleSync(authConfig.Spec.UnsupportedConfigOverrides.Raw); err != nil {
		return err
	}

	// TODO update states and handle ClusterOperator spec/status

	return nil
}

func (c *authOperator) handleSync(configOverrides []byte) error {
	route, err := c.handleRoute()
	if err != nil {
		return err
	}

	metadataConfigMap, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, getMetadataConfigMap(route))
	if err != nil {
		return err
	}

	auth, err := c.handleAuthConfig()
	if err != nil {
		return err
	}

	service, _, err := resourceapply.ApplyService(c.services, c.recorder, defaultService())
	if err != nil {
		return err
	}

	sessionSecret, err := c.expectedSessionSecret()
	if err != nil {
		return err
	}
	secret, _, err := resourceapply.ApplySecret(c.secrets, c.recorder, sessionSecret)
	if err != nil {
		return err
	}

	expectedOAuthConfigMap, syncData, err := c.handleOAuthConfig(route, configOverrides)
	if err != nil {
		return err
	}
	configMap, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, expectedOAuthConfigMap)
	if err != nil {
		return err
	}

	// deployment, have RV of all resources
	// TODO use ExpectedDeploymentGeneration func
	// TODO probably do not need every RV
	expectedDeployment := defaultDeployment(
		syncData,
		route.ResourceVersion,
		metadataConfigMap.ResourceVersion,
		auth.ResourceVersion,
		service.ResourceVersion,
		secret.ResourceVersion,
		configMap.ResourceVersion,
	)
	deployment, _, err := resourceapply.ApplyDeployment(c.deployments, c.recorder, expectedDeployment, c.getGeneration(), false)
	if err != nil {
		return err
	}

	glog.V(4).Infof("current deployment: %#v", deployment)

	return nil
}

func defaultLabels() map[string]string {
	return map[string]string{
		"app": "origin-cluster-osin-operator2",
	}
}

func defaultMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:            targetName,
		Namespace:       targetName,
		Labels:          defaultLabels(),
		Annotations:     map[string]string{},
		OwnerReferences: nil, // TODO
	}
}
