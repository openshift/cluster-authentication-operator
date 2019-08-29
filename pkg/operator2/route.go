package operator2

import (
	"bytes"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

func (c *authOperator) handleRoute(ingress *configv1.Ingress) (*routev1.Route, *corev1.Secret, string, error) {
	expectedRoute := defaultRoute(ingress)

	route, err := c.route.Get(targetName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		route, err = c.route.Create(expectedRoute)
	}
	if err != nil {
		return nil, nil, "FailedCreate", err
	}

	// assume it is unsafe to mutate route in case we go to a shared informer in the future
	existingCopy := route.DeepCopy()
	modified := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, expectedRoute.ObjectMeta)

	// this guarantees that route.Spec.Host is set to the current canonical host
	if *modified || !equality.Semantic.DeepEqual(existingCopy.Spec, expectedRoute.Spec) {
		// be careful not to print route.spec as it many contain secrets
		klog.Info("updating route")
		existingCopy.Spec = expectedRoute.Spec
		route, err = c.route.Update(existingCopy)
		if err != nil {
			return nil, nil, "FailedUpdate", err
		}
	}

	if ok := hasCanonicalHost(route, expectedRoute.Spec.Host); !ok {
		// be careful not to print route.spec as it many contain secrets
		return nil, nil, "FailedHost", fmt.Errorf("route is not available at canonical host %s: %+v", expectedRoute.Spec.Host, route.Status.Ingress)
	}

	routerSecret, err := c.secrets.Secrets(targetNamespace).Get(routerCertsLocalName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, "FailedRouterSecret", err
	}
	if reason, err := validateRouterSecret(routerSecret, ingress); err != nil {
		return nil, nil, reason, err
	}

	return route, routerSecret, "", nil
}

func defaultRoute(ingress *configv1.Ingress) *routev1.Route {
	return &routev1.Route{
		ObjectMeta: defaultMeta(),
		Spec: routev1.RouteSpec{
			Host:      ingressToHost(ingress), // mimic the behavior of subdomain
			Subdomain: "",                     // TODO once subdomain is functional, remove reliance on ingress config and just set subdomain=targetName
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
	return targetName + "." + ingress.Spec.Domain
}

func validateRouterSecret(routerSecret *corev1.Secret, ingress *configv1.Ingress) (string, error) {
	// be careful not to print the routerSecret even when it is empty

	if len(routerSecret.Data) == 0 {
		return "EmptyRouterSecret", fmt.Errorf("router secret is empty")
	}

	domain := ingress.Spec.Domain
	if len(domain) == 0 {
		return "NoIngressDomain", fmt.Errorf("ingress config has no domain")
	}

	pemCerts := routerSecret.Data[domain]
	if len(pemCerts) == 0 {
		return "NoIngressDataRouterSecret", fmt.Errorf("router secret has no data for ingress domain %s", domain)
	}

	certificates, err := crypto.CertsFromPEM(pemCerts)
	if err != nil {
		return "InvalidPEMRouterSecret", fmt.Errorf("router secret contains invalid PEM data: %v", err)
	}

	// use system roots as starting point because let's encrypt only provides an intermediate
	roots, err := x509.SystemCertPool()
	if err != nil {
		klog.Infof("failed to load system roots: %v", err)
		roots = x509.NewCertPool() // do not fail, we may have proxy roots
	}

	hasRoot := len(roots.Subjects()) > 0

	opts := x509.VerifyOptions{
		DNSName:       ingressToHost(ingress),
		Intermediates: x509.NewCertPool(),
		Roots:         roots,
	}

	var hasServer bool

	for _, certificate := range certificates {
		if !certificate.IsCA {
			continue
		}

		// consider self-signed CAs as roots
		if bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			klog.V(4).Infof("using CA %s as root", certificate.Subject.String())
			opts.Roots.AddCert(certificate)
			hasRoot = true
			continue
		}

		// consider all other CAs as intermediates
		klog.V(4).Infof("using CA %s as intermediate", certificate.Subject.String())
		opts.Intermediates.AddCert(certificate)
	}

	for _, certificate := range certificates {
		if certificate.IsCA {
			continue
		}

		if _, err := certificate.Verify(opts); err != nil {
			klog.V(4).Infof("cert %s failed verification: %v", certificate.Subject.String(), err)
			continue
		}

		klog.V(4).Infof("cert %s passed verification", certificate.Subject.String())
		hasServer = true
		break
	}

	if !hasRoot {
		return "NoRootCARouterSecret", fmt.Errorf("router secret combined with system and proxy roots contains no root CA")
	}

	if !hasServer {
		return "NoServerCertRouterSecret", fmt.Errorf("router secret has no cert for ingress domain %s", domain)
	}

	return "", nil
}
