package targetversion

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	appsv1lister "k8s.io/client-go/listers/apps/v1"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

var (
	operatorVersion = os.Getenv("OPERATOR_IMAGE_VERSION")
	operandVersion  = os.Getenv("OPERAND_IMAGE_VERSION")
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

	"AuthVersionProgressing",
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

func NewTargetVersionController(kubeInformersNamespaced informers.SharedInformerFactory, configInformers configinformer.SharedInformerFactory, routeInformer routeinformer.RouteInformer,
	oauthClient oauthclient.OAuthClientInterface, operatorClient v1helpers.OperatorClient, versionGetter status.VersionGetter, recorder events.Recorder) factory.Controller {
	c := &targetVersionController{
		deploymentLister:  kubeInformersNamespaced.Apps().V1().Deployments().Lister(),
		secretLister:      kubeInformersNamespaced.Core().V1().Secrets().Lister(),
		ingressLister:     configInformers.Config().V1().Ingresses().Lister(),
		routeLister:       routeInformer.Lister(),
		oauthClientClient: oauthClient,
		versionGetter:     versionGetter,

		operatorClient: operatorClient,
	}

	return factory.New().ResyncEvery(30*time.Second).WithInformers(
		kubeInformersNamespaced.Core().V1().Secrets().Informer(),
		kubeInformersNamespaced.Apps().V1().Deployments().Informer(),
		configInformers.Config().V1().Ingresses().Informer(),
		routeInformer.Informer(),
	).WithSync(c.sync).ToController("TargetVersion", recorder.WithComponentSuffix("target-version-controller"))
}

func (c *targetVersionController) getRoute() (*routev1.Route, []operatorv1.OperatorCondition) {
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionRouteDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get oauth-openshift route: %v", err),
			},
		}
	}
	return route, nil
}

func (c *targetVersionController) getIngressConfig() (*configv1.Ingress, []operatorv1.OperatorCondition) {
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthVersionIngressConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotFound",
			Message: fmt.Sprintf("Unable to get cluster ingress config: %v", err),
		}}
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "OAuthVersionIngressConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return ingress, nil
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

func (c *targetVersionController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	ingressConfig, ingressConditions := c.getIngressConfig()
	foundConditions = append(foundConditions, ingressConditions...)

	route, routeConditions := c.getRoute()
	foundConditions = append(foundConditions, routeConditions...)

	routeSecret, routeSecretConditions := c.getRouteSecret()
	foundConditions = append(foundConditions, routeSecretConditions...)

	deployment, deploymentConditions := c.getDeployment()
	foundConditions = append(foundConditions, deploymentConditions...)

	foundConditions = append(foundConditions, c.checkRouteHealthy(route, routeSecret, ingressConfig)...)
	foundConditions = append(foundConditions, c.checkDeploymentReady(deployment)...)
	foundConditions = append(foundConditions, c.oauthClientsReady(ctx)...)

	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}

	// TODO: Remove this as soon as we break the ordering of the main operator
	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "AuthVersionProgressing",
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		})
		// We achieved desired state
		c.setVersion("operator", operatorVersion)
		c.setVersion("oauth-openshift", operandVersion)
	} else {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:    "AuthVersionProgressing",
			Status:  operatorv1.ConditionTrue,
			Reason:  "PreConditionFailed",
			Message: fmt.Sprintf("%d degraded conditions found while working towards version", len(foundConditions)),
		})
	}

	for _, conditionType := range knownConditionNames.List() {
		// clean up existing foundConditions
		updatedCondition := operatorv1.OperatorCondition{
			Type:   conditionType,
			Status: operatorv1.ConditionFalse,
		}
		if strings.HasSuffix(conditionType, "Available") {
			updatedCondition.Status = operatorv1.ConditionTrue
		}
		if condition := v1helpers.FindOperatorCondition(foundConditions, conditionType); condition != nil {
			updatedCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(updatedCondition))
	}

	if _, _, err := v1helpers.UpdateStatus(c.operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	return nil
}

func (c *targetVersionController) checkDeploymentReady(deployment *appsv1.Deployment) []operatorv1.OperatorCondition {
	if deployment.DeletionTimestamp != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionDeploymentProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "Deleted",
				Message: "Waiting for the OAuth server deployment deletion",
			},
			{
				Type:    "OAuthVersionDeploymentAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "Deleted",
				Message: "The OAuth server deployment is being deleted",
			},
		}
	}

	if deployment.Status.AvailableReplicas > 0 && deployment.Status.UpdatedReplicas != deployment.Status.Replicas {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionDeploymentProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotReady",
				Message: fmt.Sprintf("Waiting for all OAuth server replicas to be ready (%d not ready)", deployment.Status.Replicas-deployment.Status.UpdatedReplicas),
			},
			{
				Type:    "OAuthVersionDeploymentAvailable",
				Status:  operatorv1.ConditionTrue,
				Reason:  "AsExpected",
				Message: fmt.Sprintf("%d available replicas found for OAuth Server", deployment.Status.AvailableReplicas),
			},
		}
	}

	if deployment.Generation != deployment.Status.ObservedGeneration {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionDeploymentProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GenerationNotObserved",
				Message: fmt.Sprintf("Waiting for OAuth server observed generation %d to match expected generation %d", deployment.Status.ObservedGeneration, deployment.Generation),
			},
		}
	}

	if deployment.Status.UpdatedReplicas != deployment.Status.Replicas || deployment.Status.UnavailableReplicas > 0 {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionDeploymentProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotAvailable",
				Message: fmt.Sprintf("Waiting for %d replicas of OAuth server to be avaiable", deployment.Status.UnavailableReplicas),
			},
		}
	}

	return nil
}

func (c *targetVersionController) checkRouteHealthy(route *routev1.Route, routerSecret *corev1.Secret, ingress *configv1.Ingress) []operatorv1.OperatorCondition {
	caData := routerSecretToCA(route, routerSecret, ingress)

	// if systemCABundle is not empty, append the new line to the caData
	if len(c.systemCABundle) > 0 {
		caData = append(bytes.TrimSpace(caData), []byte("\n")...)
	}

	rt, err := transport.TransportFor("", append(caData, c.systemCABundle...), nil, nil)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionRouteProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Transport not ready yet to check route %s", route.Name),
			},
			{
				Type:    "OAuthVersionRouteAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "TransportFailed",
				Message: fmt.Sprintf("Failed to build transport for route %s: %v (caData=%d)", route.Name, err, len(caData)),
			},
		}
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+route.Spec.Host+"/healthz", nil)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionRouteProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Making HTTP request to %q not successfull yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    "OAuthVersionRouteAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "RequestFailed",
				Message: fmt.Sprintf("Failed to construct HTTP request to %q: %v", "https://"+route.Spec.Host+"/healthz", err),
			},
		}
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionRouteProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Request to %q not successfull yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    "OAuthVersionRouteAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "RequestFailed",
				Message: fmt.Sprintf("HTTP request to %q failed: %v", "https://"+route.Spec.Host+"/healthz", err),
			},
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		klog.V(4).Infof("Route check failed with %q:\n%s\n", resp.Status, string(bodyBytes))
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthVersionRouteProgressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Request to %q have not returned 200 (HTTP_OK) yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    "OAuthVersionRouteAvailable",
				Status:  operatorv1.ConditionFalse,
				Reason:  "RequestFailed",
				Message: fmt.Sprintf("HTTP request to %q returned %q instead of 200", "https://"+route.Spec.Host+"/healthz", resp.Status),
			},
		}
	}

	return nil
}

func routerSecretToCA(route *routev1.Route, routerSecret *corev1.Secret, ingress *configv1.Ingress) []byte {
	var caData []byte

	// find the domain that matches our route
	if certs, ok := routerSecret.Data[ingress.Spec.Domain]; ok {
		caData = certs
	}

	// if we have no CA, use system roots (or more correctly, if we have no CERTIFICATE block)
	// TODO so this branch is effectively never taken, because the value of caData
	// is the concatenation of tls.crt and tls.key - the .crt data gets parsed
	// as a valid cert by AppendCertsFromPEM meaning ok is always true.
	// because Go is weird with how it validates TLS connections, having the actual
	// peer cert loaded in the transport is totally fine with the connection even
	// without having the CA loaded.  this is weird but it lets us tolerate scenarios
	// where we do not have the CA (i.e. admin is using a cert from an internal company CA).
	// thus the only way we take this branch is if len(caData) == 0
	if ok := x509.NewCertPool().AppendCertsFromPEM(caData); !ok {
		klog.Infof("using global CAs for %s, ingress domain=%s, cert data len=%d", route.Spec.Host, ingress.Spec.Domain, len(caData))
		return nil
	}

	return caData
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
