package operator2

import (
	"strings"

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
	"github.com/openshift/cluster-osin-operator/pkg/boilerplate/controller"
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

	userConfigPath = "/var/config/user"

	sessionKey   = "session"
	sessionMount = systemConfigPath + "/" + sessionKey
	sessionPath  = sessionMount + "/" + sessionKey

	globalConfigName = "cluster"

	machineConfigNamespace = "openshift-config-managed"
	userConfigNamespace    = "openshift-config"

	servicePort   = 443
	containerPort = 6443
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

	osinNameFilter := operator.FilterByNames(targetName)
	configNameFilter := operator.FilterByNames(globalConfigName)
	prefixFilter := getPrefixFilter()

	return operator.New("AuthenticationOperator2", c,
		operator.WithInformer(routeInformer, osinNameFilter),
		operator.WithInformer(coreInformers.Services(), osinNameFilter),
		operator.WithInformer(kubeInformersNamespaced.Apps().V1().Deployments(), osinNameFilter),

		operator.WithInformer(coreInformers.Secrets(), prefixFilter),
		operator.WithInformer(coreInformers.ConfigMaps(), prefixFilter),

		operator.WithInformer(authOpConfigInformer, configNameFilter),
		operator.WithInformer(configV1Informers.Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.OAuths(), configNameFilter),
	)
}

func (c *authOperator) Key() (metav1.Object, error) {
	return c.authOperatorConfig.Get(globalConfigName, metav1.GetOptions{})
}

func (c *authOperator) Sync(obj metav1.Object) error {
	operatorConfig := obj.(*authv1alpha1.AuthenticationOperatorConfig)

	if operatorConfig.Spec.ManagementState != operatorv1.Managed {
		return nil // TODO do something better for all states
	}

	if err := c.handleSync(operatorConfig); err != nil {
		return err
	}

	// TODO update states and handle ClusterOperator spec/status

	return nil
}

func (c *authOperator) handleSync(operatorConfig *authv1alpha1.AuthenticationOperatorConfig) error {
	route, err := c.handleRoute()
	if err != nil {
		return err
	}

	metadata, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, getMetadataConfigMap(route))
	if err != nil {
		return err
	}

	authConfig, err := c.handleAuthConfig()
	if err != nil {
		return err
	}

	service, _, err := resourceapply.ApplyService(c.services, c.recorder, defaultService())
	if err != nil {
		return err
	}

	expectedSessionSecret, err := c.expectedSessionSecret()
	if err != nil {
		return err
	}
	sessionSecret, _, err := resourceapply.ApplySecret(c.secrets, c.recorder, expectedSessionSecret)
	if err != nil {
		return err
	}

	oauthConfig, expectedCLIconfig, syncData, err := c.handleOAuthConfig(operatorConfig, route)
	if err != nil {
		return err
	}
	cliConfig, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, expectedCLIconfig)
	if err != nil {
		return err
	}

	// deployment, have RV of all resources
	// TODO use ExpectedDeploymentGeneration func
	// TODO manually get RV of all the config maps and secrets in syncData
	expectedDeployment := defaultDeployment(
		operatorConfig,
		syncData,
		operatorConfig.ResourceVersion,
		route.ResourceVersion,
		metadata.ResourceVersion,
		authConfig.ResourceVersion,
		service.ResourceVersion,
		sessionSecret.ResourceVersion,
		oauthConfig.ResourceVersion,
		cliConfig.ResourceVersion,
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

func getPrefixFilter() controller.Filter {
	names := operator.FilterByNames(targetName, servingCertName)
	prefix := func(obj metav1.Object) bool { // TODO add helper to combine filters
		return names.Add(obj) || strings.HasPrefix(obj.GetName(), userConfigPrefix)
	}
	return controller.FilterFuncs{
		AddFunc: prefix,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return prefix(newObj)
		},
		DeleteFunc: prefix,
	}
}
