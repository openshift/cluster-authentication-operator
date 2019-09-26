package operator2

import (
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
)

// TODO: only the route controller should report route status, only perform basic checks
// REMOVE: when we migrate to observedConfig
func (c *authOperator) handleRoute(ingress *configv1.Ingress) (*routev1.Route, *corev1.Secret, string, error) {
	route, err := c.route.Get("oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return nil, nil, "FailedRouteGet", err
	}

	expectedHost := ingressToHost(ingress)
	if ok := hasCanonicalHost(route, expectedHost); !ok {
		// be careful not to print route.spec as it many contain secrets
		return nil, nil, "FailedHost", fmt.Errorf("route is not available at canonical host %s: %+v", expectedHost, route.Status.Ingress)
	}

	routerSecret, err := c.secrets.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs", metav1.GetOptions{})
	if err != nil {
		return nil, nil, "FailedRouterSecretGet", err
	}

	return route, routerSecret, "", nil
}

// TODO: eventually move all route health checks to the router controller?
func routerSecretToSNI(routerSecret *corev1.Secret) []configv1.NamedCertificate {
	var out []configv1.NamedCertificate
	// make sure the output slice of named certs is sorted by domain so that the generated config is deterministic
	for _, domain := range sets.StringKeySet(routerSecret.Data).List() {
		out = append(out, configv1.NamedCertificate{
			Names: []string{"*." + domain}, // ingress domain is always a wildcard
			CertInfo: configv1.CertInfo{ // the cert and key are appended together
				CertFile: "/var/config/system/secrets/v4-0-config-system-router-certs/" + domain,
				KeyFile:  "/var/config/system/secrets/v4-0-config-system-router-certs/" + domain,
			},
		})
	}
	return out
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

func hasCanonicalHost(route *routev1.Route, canonicalHost string) bool {
	for _, ingress := range route.Status.Ingress {
		if ingress.Host != canonicalHost {
			continue
		}
		if !isIngressAdmitted(ingress) {
			continue
		}
		return true
	}
	return false
}

func isIngressAdmitted(ingress routev1.RouteIngress) bool {
	for _, condition := range ingress.Conditions {
		if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func ingressToHost(ingress *configv1.Ingress) string {
	return "oauth-openshift." + ingress.Spec.Domain
}
