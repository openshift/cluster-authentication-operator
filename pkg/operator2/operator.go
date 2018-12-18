package operator2

import (
	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	osinv1alpha1 "github.com/openshift/cluster-osin-operator/pkg/apis/osin/v1alpha1"
	"github.com/openshift/cluster-osin-operator/pkg/boilerplate/operator"
	osinclient "github.com/openshift/cluster-osin-operator/pkg/generated/clientset/versioned/typed/osin/v1alpha1"
	osininformer "github.com/openshift/cluster-osin-operator/pkg/generated/informers/externalversions/osin/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

const (
	targetName = "openshift-osin"

	metadataKey = "metadata"
	configKey   = "config.yaml"
	sessionKey  = "session"
	sessionPath = "/var/session"

	configName      = "cluster"
	configNamespace = "openshift-managed-config"
)

type osinOperator struct {
	osin osinclient.OsinInterface

	recorder events.Recorder

	route routeclient.RouteInterface

	services    corev1.ServicesGetter
	secrets     corev1.SecretsGetter
	configMaps  corev1.ConfigMapsGetter
	deployments appsv1.DeploymentsGetter

	authentication configv1client.AuthenticationInterface
	oauth          configv1client.OAuthInterface
}

func NewOsinOperator(
	osinInformer osininformer.OsinInformer,
	osinsClient osinclient.OsinsGetter,
	kubeInformersNamespaced informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteV1Interface,
	configInformers configinformer.SharedInformerFactory,
	configClient configclient.Interface,
	recorder events.Recorder,
) operator.Runner {
	c := &osinOperator{
		osin: osinsClient.Osins(targetName),

		recorder: recorder,

		route: routeClient.Routes(targetName),

		services:    kubeClient.CoreV1(),
		secrets:     kubeClient.CoreV1(),
		configMaps:  kubeClient.CoreV1(),
		deployments: kubeClient.AppsV1(),

		authentication: configClient.ConfigV1().Authentications(),
		oauth:          configClient.ConfigV1().OAuths(),
	}

	coreInformers := kubeInformersNamespaced.Core().V1()
	configV1Informers := configInformers.Config().V1()

	osinNameFilter := operator.FilterByNames(targetName)
	configNameFilter := operator.FilterByNames(configName)

	return operator.New("OsinOperator2", c,
		operator.WithInformer(osinInformer, osinNameFilter),
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

func (c *osinOperator) Key() (metav1.Object, error) {
	return c.osin.Get(targetName, metav1.GetOptions{})
}

func (c *osinOperator) Sync(obj metav1.Object) error {
	osinConfig := obj.(*osinv1alpha1.Osin)

	if osinConfig.Spec.ManagementState != operatorv1.Managed {
		return nil // TODO do something better for all states
	}

	if err := c.handleSync(osinConfig.Spec.UnsupportedConfigOverrides.Raw); err != nil {
		return err
	}

	// TODO update states and handle ClusterOperator spec/status

	return nil
}

func (c *osinOperator) handleSync(configOverrides []byte) error {
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

	secret, _, err := resourceapply.ApplySecret(c.secrets, c.recorder, c.expectedSessionSecret())
	if err != nil {
		return err
	}

	expectedOAuthConfigMap, err := c.handleOAuthConfig(configOverrides)
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
		OwnerReferences: nil, // TODO
	}
}
