package operator2

import (
	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
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
)

const (
	metadataKey = "metadata"
	configKey   = "config.yaml"
	sessionKey  = "session"
	sessionPath = "/var/session"
)

type authOperator struct {
	targetName             string
	targetNamespace        string
	configName             string
	configNamespace        string
	managedConfigNamespace string
	authOperatorConfigName string

	authOperatorConfig authopclient.AuthenticationOperatorConfigInterface

	recorder events.Recorder

	route routeclient.RouteInterface

	services    corev1.ServicesGetter
	secrets     corev1.SecretsGetter
	configMaps  corev1.ConfigMapsGetter
	deployments appsv1.DeploymentsGetter

	authentication configv1client.AuthenticationInterface
	oauth          configv1client.OAuthInterface
}

func NewAuthenticationOperator(
	targetName string,
	targetNamespace string,
	configName string,
	configNamespace string,
	managedConfigNamespace string,
	authOpConfigResourceName string,

	authOpConfigInformer authopinformer.AuthenticationOperatorConfigInformer,
	authOpConfigClient authopclient.AuthenticationOperatorConfigsGetter,
	kubeInformersNamespaced informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteV1Interface,
	configInformers configinformer.SharedInformerFactory,
	configClient configclient.Interface,
	recorder events.Recorder,
) operator.Runner {
	c := &authOperator{
		targetName:             targetName,
		targetNamespace:        targetNamespace,
		configName:             configName,
		configNamespace:        configNamespace,
		managedConfigNamespace: managedConfigNamespace,
		authOperatorConfigName: authOpConfigResourceName,

		authOperatorConfig: authOpConfigClient.AuthenticationOperatorConfigs(),

		recorder: recorder,

		route: routeClient.Routes(targetNamespace),

		services:    kubeClient.CoreV1(),
		secrets:     kubeClient.CoreV1(),
		configMaps:  kubeClient.CoreV1(),
		deployments: kubeClient.AppsV1(),

		authentication: configClient.ConfigV1().Authentications(),
		oauth:          configClient.ConfigV1().OAuths(),
	}

	coreInformers := kubeInformersNamespaced.Core().V1()
	configV1Informers := configInformers.Config().V1()

	authOpConfigNameFilter := operator.FilterByNames(c.authOperatorConfigName)
	osinNameFilter := operator.FilterByNames(c.targetName)
	configNameFilter := operator.FilterByNames(c.configName)

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
	return c.authOperatorConfig.Get(c.authOperatorConfigName, metav1.GetOptions{})
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
	glog.V(3).Infof("begin sync")

	glog.V(4).Infof("using config overrides  %q", configOverrides)

	auth, err := c.fetchAuthConfig()
	if err != nil {
		glog.V(1).Infof("falure fetching Authentication resource: %v", err)
		return err
	}
	if auth.Spec.Type == configv1.AuthenticationTypeIntegratedOAuth {
		oauth, err := c.fetchOAuthConfig()
		if err != nil || oauth == nil {
			return err
		}

		route, err := c.handleRoute()
		glog.V(5).Infof("handled route: err=%v route=%#v", err, route)
		if err != nil {
			return err
		}

		expectedOAuthConfigMap, err := c.configMapForOAuth(oauth, route, configOverrides)
		glog.V(5).Infof("got configmap for oauth: err=%v  cm=%#v", err, expectedOAuthConfigMap)
		if err != nil {
			return err
		}
		metadataConfigMap := getMetadataConfigMap(c.targetName, c.managedConfigNamespace, route)
		_, _, err = resourceapply.ApplyConfigMap(c.configMaps, c.recorder, metadataConfigMap)
		glog.V(5).Infof("applied metadata configmap: err=%v  cm=%#v", err, metadataConfigMap)
		if err != nil {
			return err
		}
		srv := defaultService(c.targetName, c.targetNamespace)
		_, _, err = resourceapply.ApplyService(c.services, c.recorder, srv)
		glog.V(5).Infof("applied service: err=%v srv=%#v", err, srv)
		if err != nil {
			return err
		}

		sessionSecret, err := c.expectedSessionSecret()
		glog.V(5).Infof("got expected session secret: err=%v name=%s namespace=%s", err, sessionSecret.GetName(), sessionSecret.GetNamespace())
		if err != nil {
			return err
		}
		secret, _, err := resourceapply.ApplySecret(c.secrets, c.recorder, sessionSecret)
		glog.V(5).Infof("applied session secret: err=%v name=%s namespace=%s", err, secret.GetName(), secret.GetNamespace())
		if err != nil {
			return err
		}
		configMap, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, expectedOAuthConfigMap)
		glog.V(5).Infof("applied oauth configmap: err=%v name=%s namespace=%s", err, expectedOAuthConfigMap.GetName(), expectedOAuthConfigMap.GetNamespace())
		if err != nil {
			return err
		}

		// deployment, have RV of all resources
		// TODO use ExpectedDeploymentGeneration func
		// TODO probably do not need every RV
		expectedDeployment := defaultDeployment(
			c.targetName,
			c.targetNamespace,
			secret.ResourceVersion,
			configMap.ResourceVersion,
		)
		_, _, err = resourceapply.ApplyDeployment(c.deployments, c.recorder, expectedDeployment, c.getGeneration(), false)
		glog.V(5).Infof("applied deployment: err=%v name=%s namespace=%s", err, expectedDeployment.GetName(), expectedDeployment.GetNamespace())
		if err != nil {
			return err
		}
	}
	_, err = c.updateAuthStatus(auth)
	glog.V(5).Infof("updated auth status: err=%v", err)
	return err
}

func defaultLabels() map[string]string {
	return map[string]string{
		"app": "cluster-authentication-operator",
	}
}
