package targetversion

import (
	"context"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	appsv1lister "k8s.io/client-go/listers/apps/v1"
	corev1lister "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

var (
	operatorVersion = os.Getenv("OPERATOR_IMAGE_VERSION")
	operandVersion  = os.Getenv("OPERAND_OAUTH_SERVER_IMAGE_VERSION")
)

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"OAuthVersionRouteDegraded",
	"OAuthVersionRouteProgressing",
	"OAuthVersionRouteAvailable",
	"OAuthVersionRouteSecretDegraded",

	"OAuthVersionIngressConfigDegraded",

	"OAuthVersionDeploymentDegraded",
	"OAuthVersionDeploymentProgressing",
	"OAuthVersionDeploymentAvailable",
)

type targetVersionController struct {
	operatorClient   v1helpers.OperatorClient
	ingressLister    configv1lister.IngressLister
	routeLister      routev1lister.RouteLister
	secretLister     corev1lister.SecretLister
	deploymentLister appsv1lister.DeploymentLister

	oauthClientClient oauthclient.OAuthClientInterface
	versionGetter     status.VersionGetter
	systemCABundle    []byte
}

func NewTargetVersionController(
	kubeInformersNamespaced informers.SharedInformerFactory,
	configInformers configinformer.SharedInformerFactory,
	routeInformer routeinformer.RouteInformer,
	oauthClient oauthclient.OAuthClientInterface,
	operatorClient v1helpers.OperatorClient,
	versionGetter status.VersionGetter,
	systemCABundle []byte,
	recorder events.Recorder,
) factory.Controller {
	c := &targetVersionController{
		deploymentLister:  kubeInformersNamespaced.Apps().V1().Deployments().Lister(),
		secretLister:      kubeInformersNamespaced.Core().V1().Secrets().Lister(),
		ingressLister:     configInformers.Config().V1().Ingresses().Lister(),
		routeLister:       routeInformer.Lister(),
		oauthClientClient: oauthClient,
		versionGetter:     versionGetter,

		operatorClient: operatorClient,
		systemCABundle: systemCABundle,
	}

	return factory.New().ResyncEvery(30*time.Second).WithInformers(
		kubeInformersNamespaced.Core().V1().Secrets().Informer(),
		kubeInformersNamespaced.Apps().V1().Deployments().Informer(),
		configInformers.Config().V1().Ingresses().Informer(),
		routeInformer.Informer(),
	).WithSync(c.sync).ToController("TargetVersion", recorder.WithComponentSuffix("target-version-controller"))
}

func (c *targetVersionController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	ingressConfig, ingressConditions := common.GetIngressConfig(c.ingressLister, "OAuthVersionIngressConfig")
	foundConditions = append(foundConditions, ingressConditions...)

	route, routeConditions := common.GetOAuthServerRoute(c.routeLister, "OAuthVersionRoute")
	foundConditions = append(foundConditions, routeConditions...)

	routeSecret, routeSecretConditions := c.getRouteSecret()
	foundConditions = append(foundConditions, routeSecretConditions...)

	deployment, deploymentConditions := c.getDeployment()
	foundConditions = append(foundConditions, deploymentConditions...)

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, common.CheckRouteHealthy(route, routeSecret, c.systemCABundle, ingressConfig, "OAuthVersionRoute")...)
	}

	if deployment != nil {
		foundConditions = append(foundConditions, common.CheckDeploymentReady(deployment, "OAuthVersionDeployment")...)
	} else {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "OAuthVersionDeploymentAvailable",
			Status: operatorv1.ConditionFalse,
			Reason: "MissingDeployment",
		})
	}

	foundConditions = append(foundConditions, c.oauthClientsReady(ctx)...)

	// We achieved desired state
	if len(foundConditions) == 0 {
		c.setVersion("operator", operatorVersion)
		c.setVersion("oauth-openshift", operandVersion)
	}

	return common.UpdateControllerConditions(c.operatorClient, knownConditionNames, foundConditions)
}

func (c *targetVersionController) getRouteSecret() (*corev1.Secret, []operatorv1.OperatorCondition) {
	routerSecret, err := c.secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthVersionRouteSecretDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "GetFailed",
			Message: fmt.Sprintf("Unable to get OAuth server route certificate secret: %v", err),
		}}
	}
	return routerSecret, nil
}

func (c *targetVersionController) getDeployment() (*appsv1.Deployment, []operatorv1.OperatorCondition) {
	deployment, err := c.deploymentLister.Deployments("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthVersionDeploymentDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "GetFailed",
			Message: fmt.Sprintf("Unable to get OAuth server deployment: %v", err),
		}}
	}
	return deployment, nil
}

func (c *targetVersionController) oauthClientsReady(ctx context.Context) []operatorv1.OperatorCondition {
	_, err := c.oauthClientClient.Get(ctx, "openshift-browser-client", metav1.GetOptions{})
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionClientsProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForBrowserClient",
				Message: fmt.Sprintf("Browser OAuth client not available yet"),
			},
			{
				Type:    "OAuthVersionClientsAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Failed to get %q OAuth client: %v", "openshift-browser-client", err),
			},
		}
	}

	_, err = c.oauthClientClient.Get(ctx, "openshift-challenging-client", metav1.GetOptions{})
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionClientsProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForChallengingClient",
				Message: fmt.Sprintf("Challenging OAuth client not available yet"),
			},
			{
				Type:    "OAuthVersionClientsAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Failed to get %q OAuth client: %v", "openshift-challenging-client", err),
			},
		}
	}

	return nil
}

func (c *targetVersionController) setVersion(operandName, version string) {
	if c.versionGetter.GetVersions()[operandName] != version {
		c.versionGetter.SetVersion(operandName, version)
	}
}
