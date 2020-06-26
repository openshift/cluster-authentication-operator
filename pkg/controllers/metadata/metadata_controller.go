package metadata

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"RouteDegraded",
	"IngressConfigDegraded",
	"AuthConfigDegraded",
	"OAuthSystemMetadataDegraded",
	"AuthMetadataProgressing",
)

type metadataController struct {
	ingressLister  configv1listers.IngressLister
	route          routeclient.RouteInterface
	secretLister   corev1listers.SecretLister
	configMaps     corev1client.ConfigMapsGetter
	authentication configv1client.AuthenticationInterface
	operatorClient v1helpers.OperatorClient
}

// NewMetadataController assure that ingress configuration is available to determine the domain suffix that this controller use to create
// a route for oauth. The controller then update the oauth metadata config map and update the cluster authentication config.
// The controller use degraded condition if any part of the process fail and use the "AuthMetadataProgressing=false" condition when the controller job is done
// and all resources exists.
func NewMetadataController(kubeInformersForTargetNamespace informers.SharedInformerFactory, configInformer configinformers.SharedInformerFactory, routeInformer routeinformer.SharedInformerFactory,
	configMaps corev1client.ConfigMapsGetter, route routeclient.RouteInterface, authentication configv1client.AuthenticationInterface, operatorClient v1helpers.OperatorClient,
	recorder events.Recorder) factory.Controller {
	c := &metadataController{
		ingressLister:  configInformer.Config().V1().Ingresses().Lister(),
		secretLister:   kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		configMaps:     configMaps,
		route:          route,
		authentication: authentication,
		operatorClient: operatorClient,
	}
	return factory.New().WithInformers(
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
		configInformer.Config().V1().Ingresses().Informer(),
		routeInformer.Route().V1().Routes().Informer(),
	).ResyncEvery(30*time.Second).WithSync(c.sync).ToController("MetadataController", recorder.WithComponentSuffix("metadata-controller"))
}

func (c *metadataController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	ingress, ingressConditions := c.getIngressConfig()
	foundConditions = append(foundConditions, ingressConditions...)

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, c.handleRoute(ctx, ingress)...)
	}

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, c.handleOAuthMetadataConfigMap(ctx, syncCtx.Recorder())...)
	}

	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, c.handleAuthConfig(ctx)...)
	}

	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}

	// TODO: Remove this as soon as we break the ordering of the main operator
	if len(foundConditions) == 0 {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "AuthMetadataProgressing",
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		})
	} else {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "AuthMetadataProgressing",
			Status: operatorv1.ConditionTrue,
			Reason: fmt.Sprintf("%d degraded conditions found while working towards metadata", len(foundConditions)),
		})
	}

	for _, conditionType := range knownConditionNames.List() {
		// clean up existing foundConditions
		updatedCondition := operatorv1.OperatorCondition{
			Type:   conditionType,
			Status: operatorv1.ConditionFalse,
		}
		if condition := v1helpers.FindOperatorCondition(foundConditions, conditionType); condition != nil {
			updatedCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(updatedCondition))
	}

	if _, _, err := v1helpers.UpdateStatus(c.operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	// retry faster when we got degraded condition
	// if len(foundConditions) > 0 {
	if v1helpers.IsOperatorConditionTrue(foundConditions, "AuthMetadataProgressing") {
		return factory.SyntheticRequeueError
	}

	return nil
}

func (c *metadataController) getIngressConfig() (*configv1.Ingress, []operatorv1.OperatorCondition) {
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "IngressConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotFound",
			Message: fmt.Sprintf("Unable to get cluster ingress config: %v", err),
		}}
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, []operatorv1.OperatorCondition{{
			Type:    "IngressConfigDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return ingress, nil
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
	if _, _, err := resourceapply.ApplyConfigMap(c.configMaps, recorder, getOAuthMetadataConfigMap(route.Status.Ingress[0].Host)); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "OAuthSystemMetadataDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return nil
}

func (c *metadataController) handleRoute(ctx context.Context, ingress *configv1.Ingress) []operatorv1.OperatorCondition {
	expectedRoute := getOauthRoute(ingress)

	route, err := c.route.Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		route, err = c.route.Create(ctx, expectedRoute, metav1.CreateOptions{})
	}
	if err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "RouteDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "FailedCreate",
			Message: fmt.Sprintf("Unable to get or create required route %s/%s: %v", expectedRoute.Namespace, expectedRoute.Name, err),
		}}
	}

	// assume it is unsafe to mutate route in case we go to a shared informer in the future
	existingCopy := route.DeepCopy()
	modified := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, expectedRoute.ObjectMeta)

	// this guarantees that route.Spec.Host is set to the current canonical host
	if *modified || !equality.Semantic.DeepEqual(existingCopy.Spec, expectedRoute.Spec) {
		// be careful not to print route.spec as it many contain secrets
		existingCopy.Spec = expectedRoute.Spec
		route, err = c.route.Update(ctx, existingCopy, metav1.UpdateOptions{})
		if err != nil {
			return []operatorv1.OperatorCondition{{
				Type:    "RouteDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "FailedUpdate",
				Message: fmt.Sprintf("Unable to update route %s/%s: %v", expectedRoute.Namespace, expectedRoute.Name, err),
			}}
		}
	}

	if ok := routeHasCanonicalHost(route, expectedRoute.Spec.Host); !ok {
		// be careful not to print route.spec as it many contain secrets
		return []operatorv1.OperatorCondition{{
			Type:    "RouteDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "InvalidCanonicalHost",
			Message: fmt.Sprintf("Route is not available at canonical host %s: %+v", expectedRoute.Spec.Host, route.Status.Ingress),
		}}
	}

	if _, err := c.secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs"); err != nil {
		return []operatorv1.OperatorCondition{{
			Type:    "RouteDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "SystemRouterCertsNotFound",
			Message: fmt.Sprintf("Unable to get %q: %v", "v4-0-config-system-router-certs", err),
		}}
	}

	return nil
}

// FIXME: we need to handle Authentication config object properly, namely:
// - honor Type field being set to none and don't create the OSIN
//   deployment in that case
// - the OAuthMetadata settings should be better respected in the code,
//   currently there is no special handling around it (see configmap.go).
// - the WebhookTokenAuthenticators field is currently not being handled
//   anywhere
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
			Reason:  "FailedCreate",
			Message: fmt.Sprintf("Unable to get or create cluster authentication config: %v", err),
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

func routeHasCanonicalHost(route *routev1.Route, canonicalHost string) bool {
	for _, ingress := range route.Status.Ingress {
		if ingress.Host != canonicalHost {
			continue
		}
		for _, condition := range ingress.Conditions {
			if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func getOauthRoute(ingressConfig *configv1.Ingress) *routev1.Route {
	// emulates server-side defaulting as in https://github.com/openshift/openshift-apiserver/blob/master/pkg/route/apis/route/configv1listers/defaults.go
	// TODO: replace with server-side apply
	var weightVal int32 = 100

	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth-openshift",
			Namespace: "openshift-authentication",
			Labels: map[string]string{
				"app": "oauth-openshift",
			},
			Annotations:     map[string]string{},
			OwnerReferences: nil, // TODO
		},
		Spec: routev1.RouteSpec{
			Host:      "oauth-openshift." + ingressConfig.Spec.Domain, // mimic the behavior of subdomain
			Subdomain: "",                                             // TODO once subdomain is functional, remove reliance on ingress config and just set subdomain=targetName
			To: routev1.RouteTargetReference{
				Kind:   "Service",
				Name:   "oauth-openshift",
				Weight: &weightVal,
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(6443),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationPassthrough,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
			WildcardPolicy: routev1.WildcardPolicyNone, // emulates server-side defaulting, see the link above
		},
	}
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
