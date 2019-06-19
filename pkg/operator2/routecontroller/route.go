package routecontroller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// FIXME: maybe still keep in a separate file
func (c *routeController) handleIngress() (*configv1.Ingress, error) {
	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return nil, err
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, fmt.Errorf("ingress has empty spec.domain: %#v", ingress)
	}
	return ingress, nil
}

//--------------

func (c *routeController) handleRoute(routeClient routeclient.RouteInterface, ingress *configv1.Ingress, route *routev1.Route) (*routev1.Route, string, error) {
	expectedRoute := defaultRoute(ingress)

	// assume it is unsafe to mutate route in case we go to a shared informer in the future
	existingCopy := route.DeepCopy()
	modified := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, expectedRoute.ObjectMeta)

	// this guarantees that route.Spec.Host is set to the current canonical host
	if *modified || !equality.Semantic.DeepEqual(existingCopy.Spec, expectedRoute.Spec) {
		// be careful not to print route.spec as it many contain secrets
		klog.Info("updating route")
		existingCopy.Spec = expectedRoute.Spec

		var err error
		route, err = routeClient.Update(existingCopy)
		if err != nil {
			return nil, "FailedUpdate", err
		}
	}

	if ok := hasCanonicalHost(route, expectedRoute.Spec.Host); !ok {
		// be careful not to print route.spec as it many contain secrets
		return nil, "FailedHost", fmt.Errorf("route is not available at canonical host %s: %+v", expectedRoute.Spec.Host, route.Status.Ingress)
	}

	return route, "", nil
}

func defaultRoute(ingress *configv1.Ingress) *routev1.Route {
	// emulates server-side defaulting as in https://github.com/openshift/openshift-apiserver/blob/master/pkg/route/apis/route/v1/defaults.go
	// TODO: replace with server-side apply
	var weightVal int32 = 100

	return &routev1.Route{
		ObjectMeta: defaultMeta(),
		Spec: routev1.RouteSpec{
			Host:      ingressToHost(ingress), // mimic the behavior of subdomain
			Subdomain: "",                     // TODO once subdomain is functional, remove reliance on ingress config and just set subdomain=targetName
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

func defaultRouteNoHost(name string) *routev1.Route {
	// emulates server-side defaulting as in https://github.com/openshift/openshift-apiserver/blob/master/pkg/route/apis/route/v1/defaults.go
	// TODO: replace with server-side apply
	var weightVal int32 = 100

	objMeta := defaultMeta()
	objMeta.Name = name

	return &routev1.Route{
		ObjectMeta: objMeta,
		Spec: routev1.RouteSpec{
			Subdomain: "", // TODO once subdomain is functional, remove reliance on ingress config and just set subdomain=targetName
			To: routev1.RouteTargetReference{
				Kind:   "Service",
				Name:   name,
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
