package operator2

import (
	"crypto/x509"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
)

func (c *authOperator) handleRoute() (*routev1.Route, *corev1.Secret, error) {
	route, err := c.route.Get(targetName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		route, err = c.route.Create(defaultRoute())
	}
	if err != nil {
		return nil, nil, err
	}

	if len(route.Spec.Host) == 0 {
		return nil, nil, fmt.Errorf("route has no host: %#v", route)
	}

	if err := isValidRoute(route); err != nil {
		// delete the route so that it is replaced with the proper one in next reconcile loop
		klog.Infof("deleting invalid route: %#v", route)
		opts := &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &route.UID}}
		if err := c.route.Delete(route.Name, opts); err != nil && !errors.IsNotFound(err) {
			klog.Infof("failed to delete invalid route: %v", err)
		}
		return nil, nil, err
	}

	routerSecret, err := c.secrets.Secrets(targetName).Get(routerCertsLocalName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	if len(routerSecret.Data) == 0 {
		return nil, nil, fmt.Errorf("router secret is empty: %#v", routerSecret)
	}

	return route, routerSecret, nil
}

func isValidRoute(route *routev1.Route) error {
	// TODO: return all errors at once
	// TODO error when fields that should be empty are set

	// get the expected settings from the default route
	expectedRoute := defaultRoute()
	expName := expectedRoute.Spec.To.Name
	expPort := expectedRoute.Spec.Port.TargetPort.IntValue()
	expTLSTermination := expectedRoute.Spec.TLS.Termination
	expInsecureEdgeTerminationPolicy := expectedRoute.Spec.TLS.InsecureEdgeTerminationPolicy

	if route.Spec.To.Name != expName {
		return fmt.Errorf("route targets a wrong service - needs %s: %#v", expName, route)
	}

	if route.Spec.Port.TargetPort.IntValue() != expPort {
		return fmt.Errorf("expected port '%d' for route: %#v", expPort, route)
	}

	if route.Spec.TLS == nil {
		return fmt.Errorf("TLS needs to be configured for route: %#v", route)
	}

	if route.Spec.TLS.Termination != expTLSTermination {
		return fmt.Errorf("route contains wrong TLS termination - '%s' is required: %#v", expTLSTermination, route)
	}

	if route.Spec.TLS.InsecureEdgeTerminationPolicy != expInsecureEdgeTerminationPolicy {
		return fmt.Errorf("route contains wrong insecure termination policy - '%s' is required: %#v", expInsecureEdgeTerminationPolicy, route)
	}

	return nil
}

func defaultRoute() *routev1.Route {
	return &routev1.Route{
		ObjectMeta: defaultMeta(),
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: targetName,
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(containerPort),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationPassthrough,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
		},
	}
}

func routerSecretToSNI(routerSecret *corev1.Secret) []configv1.NamedCertificate {
	var out []configv1.NamedCertificate
	for domain := range routerSecret.Data {
		out = append(out, configv1.NamedCertificate{
			Names: []string{"*." + domain}, // ingress domain is always a wildcard
			CertInfo: configv1.CertInfo{ // the cert and key are appended together
				CertFile: routerCertsLocalMount + "/" + domain,
				KeyFile:  routerCertsLocalMount + "/" + domain,
			},
		})
	}
	return out
}

func routerSecretToCA(route *routev1.Route, routerSecret *corev1.Secret) []byte {
	var (
		caData        []byte
		longestDomain string
	)

	// find the longest domain that matches our route
	// TODO drop this logic once we fix how we determine our route host
	for domain, certs := range routerSecret.Data {
		if strings.HasSuffix(route.Spec.Host, "."+domain) && len(domain) > len(longestDomain) {
			caData = certs
			longestDomain = domain
		}
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
		klog.Infof("using global CAs for %s, ingress domain=%s, cert data len=%d", route.Spec.Host, longestDomain, len(caData))
		return nil
	}

	return caData
}
