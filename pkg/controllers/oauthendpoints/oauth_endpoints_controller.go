package oauthendpoints

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	corev1listers "k8s.io/client-go/listers/core/v1"

	routev1 "github.com/openshift/api/route/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	routev1informers "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/libs/endpointaccessible"
)

// NewOAuthRouteCheckController returns a controller that checks the health of authentication route.
func NewOAuthRouteCheckController(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForTargetNS informers.SharedInformerFactory,
	kubeInformersForConfigManagedNS informers.SharedInformerFactory,
	routeInformerNamespaces routev1informers.RouteInformer,
	ingressInformerAllNamespaces configv1informers.IngressInformer,
	systemCABundle []byte,
	recorder events.Recorder,
) factory.Controller {
	cmLister := kubeInformersForConfigManagedNS.Core().V1().ConfigMaps().Lister()
	cmInformer := kubeInformersForConfigManagedNS.Core().V1().ConfigMaps().Informer()

	secretLister := kubeInformersForTargetNS.Core().V1().Secrets().Lister()
	secretInformer := kubeInformersForTargetNS.Core().V1().Secrets().Informer()
	routeLister := routeInformerNamespaces.Lister()
	routeInformer := routeInformerNamespaces.Informer()
	ingressLister := ingressInformerAllNamespaces.Lister()
	ingressInformer := ingressInformerAllNamespaces.Informer()

	endpointListFunc := func() ([]string, error) {
		return listOAuthRoutes(routeLister)
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthRouteTLSConfig(cmLister, secretLister, ingressLister, systemCABundle)
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthServerRoute",
		operatorClient,
		endpointListFunc, getTLSConfigFunc,
		[]factory.Informer{
			cmInformer,
			secretInformer,
			routeInformer,
			ingressInformer,
		},
		recorder)
}

// NewOAuthServiceCheckController returns a controller that checks the health of authentication service.
func NewOAuthServiceCheckController(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForTargetNS informers.SharedInformerFactory,
	recorder events.Recorder,
) factory.Controller {
	endpointsListFunc := func() ([]string, error) {
		return listOAuthServices(kubeInformersForTargetNS.Core().V1().Services().Lister())
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthEndpointTLSConfig(kubeInformersForTargetNS.Core().V1().ConfigMaps().Lister())
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthServerService",
		operatorClient,
		endpointsListFunc, getTLSConfigFunc,
		[]factory.Informer{
			kubeInformersForTargetNS.Core().V1().ConfigMaps().Informer(),
			kubeInformersForTargetNS.Core().V1().Services().Informer(),
		},
		recorder)
}

// NewOAuthServiceEndpointsCheckController returns a controller that checks the health of authentication service
// endpoints.
func NewOAuthServiceEndpointsCheckController(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForTargetNS informers.SharedInformerFactory,
	recorder events.Recorder,
) factory.Controller {
	endpointsListFn := func() ([]string, error) {
		return listOAuthServiceEndpoints(kubeInformersForTargetNS.Core().V1().Endpoints().Lister())
	}

	getTLSConfigFunc := func() (*tls.Config, error) {
		return getOAuthEndpointTLSConfig(kubeInformersForTargetNS.Core().V1().ConfigMaps().Lister())
	}

	return endpointaccessible.NewEndpointAccessibleController(
		"OAuthServerServiceEndpoints",
		operatorClient,
		endpointsListFn, getTLSConfigFunc,
		[]factory.Informer{
			kubeInformersForTargetNS.Core().V1().Endpoints().Informer(),
			kubeInformersForTargetNS.Core().V1().ConfigMaps().Informer(),
		},
		recorder)
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
			for _, condition := range ingress.Conditions {
				if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
					results = append(results, ingress.Host)
					break
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("route \"openshift-authentication/oauth-openshift\": status does not have a host address")
	}
	return toHealthzURL(results), nil
}

func getOAuthRouteTLSConfig(cmLister corev1listers.ConfigMapLister, secretLister corev1listers.SecretLister, ingressLister configv1lister.IngressLister, systemCABundle []byte) (*tls.Config, error) {
	// get default router CA cert cm
	defaultIngressCertCM, err := cmLister.ConfigMaps("openshift-config-managed").Get("default-ingress-cert")
	if err != nil {
		return nil, err
	}

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

	defaultRouterCAPEM, ok := defaultIngressCertCM.Data["ca-bundle.crt"]
	if !ok {
		return nil, fmt.Errorf("the openshift-config-managed/default-ingress-cert CM does not contain the \"ca-bundle.crt\" key")
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM([]byte(defaultRouterCAPEM)); !ok {
		klog.V(5).Infof("the default ingress CA bundle did not contain any PEM certificates")
		return nil, nil
	}

	// find the domain that matches our route
	routerCertKey, ok := routerSecret.Data[ingress.Spec.Domain]
	if !ok {
		klog.V(5).Infof("unable to find router certs for domain %s", ingress.Spec.Domain)
		return nil, nil
	}

	if ok := rootCAs.AppendCertsFromPEM(routerCertKey); !ok {
		klog.V(5).Infof("the router certs bundle did not contain any PEM certificates for domain %s", ingress.Spec.Domain)
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

func getOAuthEndpointTLSConfig(cmLister corev1listers.ConfigMapLister) (*tls.Config, error) {
	serviceCACM, err := cmLister.ConfigMaps("openshift-authentication").Get("v4-0-config-system-service-ca")
	if err != nil {
		return nil, err
	}

	// find the domain that matches our route
	if _, ok := serviceCACM.Data["service-ca.crt"]; !ok {
		return nil, fmt.Errorf("\"service-ca.crt\" key of the \"openshift-authentication/v4-0-config-system-service-ca\" CM is empty")
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM([]byte(serviceCACM.Data["service-ca.crt"])); !ok {
		return nil, fmt.Errorf("no certificates could be parsed from the service-ca CA bundle")
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
