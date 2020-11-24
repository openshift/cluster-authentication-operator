package common

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

func CheckRouteHealthy(route *routev1.Route, routerSecret *corev1.Secret, systemCABundle []byte, ingress *configv1.Ingress, conditionPrefix string) []operatorv1.OperatorCondition {
	if _, _, err := routeapihelpers.IngressURI(route, route.Spec.Host); err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Route %q was not admitted yet", route.Name),
			},
			{
				Type:    conditionPrefix + "Available",
				Status:  operatorv1.ConditionFalse,
				Reason:  "RouteNotReady",
				Message: err.Error(),
			},
		}
	}
	caData := routerSecretToCA(route, routerSecret, ingress)

	// if systemCABundle is not empty, append the new line to the caData
	if len(systemCABundle) > 0 {
		caData = append(bytes.TrimSpace(caData), []byte("\n")...)
	}

	rt, err := transport.TransportFor("", append(caData, systemCABundle...), nil, nil)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Transport not ready yet to check route %s", route.Name),
			},
			{
				Type:    conditionPrefix + "Available",
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
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Making HTTP request to %q not successful yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    conditionPrefix + "Available",
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
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Request to %q not successful yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    conditionPrefix + "Available",
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
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "WaitingForRoute",
				Message: fmt.Sprintf("Request to %q have not returned 200 (HTTP_OK) yet", "https://"+route.Spec.Host+"/healthz"),
			},
			{
				Type:    conditionPrefix + "Available",
				Status:  operatorv1.ConditionFalse,
				Reason:  "RequestFailed",
				Message: fmt.Sprintf("HTTP request to %q returned %q instead of 200", "https://"+route.Spec.Host+"/healthz", resp.Status),
			},
		}
	}

	return nil
}

func GetOAuthServerRoute(routeLister routev1lister.RouteLister, conditionPrefix string) (*routev1.Route, []operatorv1.OperatorCondition) {
	route, err := routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil && os.IsNotExist(err) {
		return nil, []operatorv1.OperatorCondition{{
			Type:    conditionPrefix + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotFound",
			Message: fmt.Sprintf("The OAuth server route not found: %v", err),
		}}
	}
	if err != nil {
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Degraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get oauth-openshift route: %v", err),
			},
		}
	}
	return route, nil
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
