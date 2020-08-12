package oauthendpoints

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"

	"k8s.io/klog/v2"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	routev1informers "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/libs/endpointaccessible"

	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// NewOAuthRouteCheckController returns a controller that checks the health of authentication route.
func NewOAuthRouteCheckController(
	operatorClient v1helpers.OperatorClient,
	secretInformerForNamespaces corev1informers.SecretInformer,
	routeInformerNamespaces routev1informers.RouteInformer,
	ingressInformerAllNamespaces configv1informers.IngressInformer,
	systemCABundle []byte,
	recorder events.Recorder,
) factory.Controller {
	secretLister := secretInformerForNamespaces.Lister()
	secretInformer := secretInformerForNamespaces.Informer()
	routeLister := routeInformerNamespaces.Lister()
	routeInformer := routeInformerNamespaces.Informer()
	ingressLister := ingressInformerAllNamespaces.Lister()
	ingressInformer := ingressInformerAllNamespaces.Informer()

	endpointListFunc := func() ([]string, error) {
		return listOAuthRoutes(routeLister)
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthRouteTLSConfig(secretLister, ingressLister, systemCABundle)
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthRouteCheck",
		operatorClient, endpointListFunc, getTLSConfigFunc, []factory.Informer{routeInformer, secretInformer, ingressInformer}, recorder)
}

// NewOAuthServiceCheckController returns a controller that checks the health of authentication service.
func NewOAuthServiceCheckController(
	operatorClient v1helpers.OperatorClient,
	secretInformerForNamespaces corev1informers.SecretInformer,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	secretLister := secretInformerForNamespaces.Lister()
	secretInformer := secretInformerForNamespaces.Informer()
	serviceLister := corev1Informers.Services().Lister()
	serviceInformer := corev1Informers.Services().Informer()

	endpointsListFunc := func() ([]string, error) {
		return listOAuthServices(serviceLister)
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthEndpointTLSConfig(secretLister)
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthServiceCheck",
		operatorClient, endpointsListFunc, getTLSConfigFunc, []factory.Informer{serviceInformer, secretInformer}, recorder)
}

// NewOAuthServiceEndpointsCheckController returns a controller that checks the health of authentication service
// endpoints.
func NewOAuthServiceEndpointsCheckController(
	operatorClient v1helpers.OperatorClient,
	secretInformerForNamespaces corev1informers.SecretInformer,
	corev1Informers corev1informers.Interface,
	recorder events.Recorder,
) factory.Controller {
	secretLister := secretInformerForNamespaces.Lister()
	secretInformer := secretInformerForNamespaces.Informer()
	endpointsLister := corev1Informers.Endpoints().Lister()
	endpointsInformer := corev1Informers.Endpoints().Informer()

	endpointsListFn := func() ([]string, error) {
		return listOAuthServiceEndpoints(endpointsLister)
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthEndpointTLSConfig(secretLister)
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthServiceEndpointsCheck",
		operatorClient, endpointsListFn, getTLSConfigFunc, []factory.Informer{endpointsInformer, secretInformer}, recorder)
}

func listOAuthServiceEndpoints(endpointsLister corev1listers.EndpointsLister) ([]string, error) {
	var results []string
	endpoints, err := endpointsLister.Endpoints("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return nil, err
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

func listOAuthServices(serviceLister corev1listers.ServiceLister) ([]string, error) {
	var results []string
	service, err := serviceLister.Services("openshift-authentication").Get("oauth-openshift")
	if err != nil {
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

func listOAuthRoutes(routeLister routev1listers.RouteLister) ([]string, error) {
	var results []string
	route, err := routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return nil, err
	}
	for _, ingress := range route.Status.Ingress {
		if len(ingress.Host) > 0 {
			results = append(results, ingress.Host)
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("route \"openshift-authentication/oauth-openshift\": status does not have a host address")
	}
	return toHealthzURL(results), nil
}

func getOAuthRouteTLSConfig(secretLister corev1listers.SecretLister, ingressLister configv1lister.IngressLister, systemCABundle []byte) (*tls.Config, error) {
	ingress, err := ingressLister.Get("cluster")
	if err != nil {
		return nil, err
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, fmt.Errorf("ingress config domain cannot be empty")
	}

	routerSecret, err := secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs")
	if err != nil {
		return nil, err
	}

	// find the domain that matches our route
	if _, ok := routerSecret.Data[ingress.Spec.Domain]; !ok {
		klog.V(5).Infof("unable to find router certs for domain %s", ingress.Spec.Domain)
		return nil, nil
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(routerSecret.Data[ingress.Spec.Domain]); !ok {
		klog.V(5).Infof("failed to parse router certs for domain %s", ingress.Spec.Domain)
		return nil, nil
	}

	if len(systemCABundle) > 0 {
		if ok := rootCAs.AppendCertsFromPEM(systemCABundle); !ok {
			klog.V(5).Infof("the system CA bundle did not contain any PEM certificates")
			return nil, nil
		}
	}

	return &tls.Config{
		RootCAs: rootCAs,
	}, nil
}

func getOAuthEndpointTLSConfig(secretLister corev1listers.SecretLister) (*tls.Config, error) {
	serviceSecret, err := secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-serving-cert")
	if err != nil {
		return nil, err
	}

	// find the domain that matches our route
	if _, ok := serviceSecret.Data["tls.crt"]; !ok {
		return nil, fmt.Errorf("unable to find service ca bundle")
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(serviceSecret.Data["tls.crt"]); !ok {
		return nil, fmt.Errorf("no certificates could be parsed from the service ca bundle")
	}
	return &tls.Config{
		RootCAs: rootCAs,
		// Specify a host name allowed by the serving cert of the
		// endpoints to ensure that TLS validates successfully. The
		// serving cert the endpoint uses does not include IP SANs
		// so accessing the endpoint via IP would otherwise result
		// in validation failure.
		ServerName: "oauth-openshift.openshift-authentication.svc",
	}, nil
}

func toHealthzURL(urls []string) []string {
	var res []string
	for _, url := range urls {
		res = append(res, "https://"+url+"/healthz")
	}
	return res
}
