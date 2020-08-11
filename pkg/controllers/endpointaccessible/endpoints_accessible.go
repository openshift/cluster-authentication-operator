package endpointaccessible

import (
	"fmt"
	"net"
	"strconv"

	routev1informers "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// NewOAuthRouteCheckController returns a controller that checks the health of authentication route.
func NewOAuthRouteCheckController(
	operatorClient v1helpers.OperatorClient,
	routeInformerNamespaces routev1informers.RouteInformer,
	recorder events.Recorder,
) factory.Controller {
	routeLister := routeInformerNamespaces.Lister()
	routeInformer := routeInformerNamespaces.Informer()
	endpointListFunc := func() ([]string, error) {
		return listOAuthRoutes(routeLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthRouteCheck",
		operatorClient, endpointListFunc, []factory.Informer{routeInformer}, recorder)
}

// NewOAuthServiceCheckController returns a controller that checks the health of authentication service.
func NewOAuthServiceCheckController(
	operatorClient v1helpers.OperatorClient,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	serviceLister := corev1Informers.Services().Lister()
	serviceInformer := corev1Informers.Services().Informer()
	endpointsListFunc := func() ([]string, error) {
		return listOAuthServices(serviceLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthServiceCheck",
		operatorClient, endpointsListFunc, []factory.Informer{serviceInformer}, recorder)
}

// NewOAuthServiceEndpointsCheckController returns a controller that checks the health of authentication service
// endpoints.
func NewOAuthServiceEndpointsCheckController(
	operatorClient v1helpers.OperatorClient,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	endpointsLister := corev1Informers.Endpoints().Lister()
	endpointsInformer := corev1Informers.Endpoints().Informer()

	endpointsListFn := func() ([]string, error) {
		return listOAuthServiceEndpoints(endpointsLister, recorder)
	}

	return NewEndpointAccessibleController(
		"OAuthServiceEndpointsCheck",
		operatorClient, endpointsListFn, []factory.Informer{endpointsInformer}, recorder)
}

func listOAuthServiceEndpoints(endpointsLister corev1listers.EndpointsLister, recorder events.Recorder) ([]string, error) {
	var results []string
	endpoints, err := endpointsLister.Endpoints("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthServiceEndpointsCheck", "failed to get oauth service endpoints: %v", err)
		return results, nil
	}
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			for _, port := range subset.Ports {
				results = append(results, net.JoinHostPort(address.IP, strconv.Itoa(int(port.Port))))
			}
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("oauth service endpoints are not ready")
	}
	return toHealthzURL(results), nil
}

func listOAuthServices(serviceLister corev1listers.ServiceLister, recorder events.Recorder) ([]string, error) {
	var results []string
	service, err := serviceLister.Services("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthServiceCheck", "failed to get oauth service: %v", err)
		return nil, err
	}
	for _, port := range service.Spec.Ports {
		results = append(results, net.JoinHostPort(service.Spec.ClusterIP, strconv.Itoa(int(port.Port))))
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no valid oauth services found")
	}
	return toHealthzURL(results), nil
}

func listOAuthRoutes(routeLister routev1listers.RouteLister, recorder events.Recorder) ([]string, error) {
	var results []string
	route, err := routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		recorder.Warningf("OAuthRouteCheck", "failed to get oauth route: %v", err)
		return nil, err
	}
	for _, ingress := range route.Status.Ingress {
		if len(ingress.Host) > 0 {
			results = append(results, ingress.Host)
		}
	}
	if len(results) == 0 {
		recorder.Warningf("OAuthRouteCheck", "route status does not have host address")
		return nil, fmt.Errorf("route status does not have host address")
	}
	return toHealthzURL(results), nil
}
