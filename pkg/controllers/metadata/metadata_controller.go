package metadata

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"IngressConfigDegraded",
	"AuthConfigDegraded",
	"OAuthSystemMetadataDegraded",
)

type metadataController struct {
	controllerInstanceName string
	ingressLister          configv1listers.IngressLister
	route                  routeclient.RouteInterface
	secretLister           corev1listers.SecretLister
	configMapLister        corev1listers.ConfigMapLister
	configMaps             corev1client.ConfigMapsGetter
	authentication         configv1client.AuthenticationInterface
	operatorClient         v1helpers.OperatorClient
	authConfigChecker      common.AuthConfigChecker
}

// NewMetadataController assure that ingress configuration is available to determine the domain suffix that this controller use to create
// a route for oauth. The controller then update the oauth metadata config map and update the cluster authentication config.
// The controller use degraded condition if any part of the process fail and use the "AuthMetadataProgressing=false" condition when the controller job is done
// and all resources exists.
func NewMetadataController(instanceName string,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	configInformer configinformers.SharedInformerFactory,
	routeInformer routeinformer.SharedInformerFactory,
	configMaps corev1client.ConfigMapsGetter,
	route routeclient.RouteInterface,
	authentication configv1client.AuthenticationInterface,
	operatorClient v1helpers.OperatorClient,
	authConfigChecker common.AuthConfigChecker,
	recorder events.Recorder,
) factory.Controller {
	c := &metadataController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "Metadata"),
		ingressLister:          configInformer.Config().V1().Ingresses().Lister(),
		secretLister:           kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		configMapLister:        kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		configMaps:             configMaps,
		route:                  route,
		authentication:         authentication,
		operatorClient:         operatorClient,
		authConfigChecker:      authConfigChecker,
	}
	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
		configInformer.Config().V1().Ingresses().Informer(),
		routeInformer.Route().V1().Routes().Informer(),
		authConfigChecker.KubeAPIServers().Informer(),
	).ResyncEvery(wait.Jitter(time.Minute, 1.0)).WithSync(c.sync).ToController(c.controllerInstanceName, recorder.WithComponentSuffix("metadata-controller"))
}

func (c *metadataController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		if err := c.removeOperands(ctx); err != nil {
			return err
		}

		return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, knownConditionNames, nil)
	}

	foundConditions := []operatorv1.OperatorCondition{}

	foundConditions = append(foundConditions, c.handleOAuthMetadataConfigMap(ctx, syncCtx.Recorder())...)

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, c.handleAuthConfig(ctx)...)
	}

	return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, knownConditionNames, foundConditions)
}

func (c *metadataController) handleOAuthMetadataConfigMap(ctx context.Context, recorder events.Recorder) []operatorv1.OperatorCondition {
	route, err := c.route.Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "RouteDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "FailedGet",
			Message: fmt.Sprintf("Unable to get required route %s/%s: %v", "openshift-authentication", "oauth-openshift", err),
		}}
	}
	if len(route.Status.Ingress) == 0 || len(route.Status.Ingress[0].Host) == 0 {
		return []operatorv1.OperatorCondition{{
			Type:    "RouteDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotReady",
			Message: fmt.Sprintf("Route %s/%s is not ready: The ingress host is empty in route status", "openshift-authentication", "oauth-openshift"),
		}}
	}
	// make sure API server sees our metadata as soon as we've got a route with a host
	if _, _, err := resourceapply.ApplyConfigMap(ctx, c.configMaps, recorder, getOAuthMetadataConfigMap(route.Status.Ingress[0].Host)); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "OAuthSystemMetadataDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return nil
}

// FIXME: we need to handle Authentication config object properly, namely:
//   - honor Type field being set to none and don't create the OSIN
//     deployment in that case
//   - the WebhookTokenAuthenticators field is currently not being handled
//     anywhere
//
// Note that the configMap from the reference in the OAuthMetadata field is
// used to fill the data in the /.well-known/oauth-authorization-server
// endpoint, but since that endpoint belongs to the apiserver, its syncing is
// handled in cluster-kube-apiserver-operator
func (c *metadataController) handleAuthConfig(ctx context.Context) []operatorv1.OperatorCondition {
	// always make sure this function does not rely on defaulting from defaultAuthConfig
	authConfigNoDefaults, err := c.authentication.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "AuthConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "FailedGet",
			Message: fmt.Sprintf("Unable to get cluster authentication config: %v", err),
		}}
	}

	expectedReference := configv1.ConfigMapNameReference{
		Name: "oauth-openshift",
	}

	if authConfigNoDefaults.Status.IntegratedOAuthMetadata == expectedReference {
		return nil
	}

	authConfigNoDefaults.Status.IntegratedOAuthMetadata = expectedReference
	if _, err := c.authentication.UpdateStatus(ctx, authConfigNoDefaults, metav1.UpdateOptions{}); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "AuthConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "UpdateStatusFailed",
			Message: fmt.Sprintf("Unable to update status of cluster authentication config: %v", err),
		}}
	}
	return nil
}

func (c *metadataController) removeOperands(ctx context.Context) error {
	if _, err := c.configMapLister.ConfigMaps("openshift-authentication").Get("v4-0-config-system-metadata"); errors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	err := c.configMaps.ConfigMaps("openshift-authentication").Delete(ctx, "v4-0-config-system-metadata", metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	return nil
}

func getOAuthMetadata(host string) string {
	stubMetadata := `
{
  "issuer": "https://%s",
  "authorization_endpoint": "https://%s/oauth/authorize",
  "token_endpoint": "https://%s/oauth/token",
  "scopes_supported": [
    "user:check-access",
    "user:full",
    "user:info",
    "user:list-projects",
    "user:list-scoped-projects"
  ],
  "response_types_supported": [
    "code",
    "token"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit"
  ],
  "code_challenge_methods_supported": [
    "plain",
    "S256"
  ]
}
`
	return strings.TrimSpace(fmt.Sprintf(stubMetadata, host, host, host))
}

func getOAuthMetadataConfigMap(routeHost string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "v4-0-config-system-metadata",
			Namespace: "openshift-authentication",
			Labels: map[string]string{
				"app": "oauth-openshift",
			},
			Annotations: map[string]string{},
		},
		Data: map[string]string{
			configv1.OAuthMetadataKey: getOAuthMetadata(routeHost),
		},
	}
}
