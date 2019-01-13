package operator2

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	routev1 "github.com/openshift/api/route/v1"
)

func (c *authOperator) handleRoute() (*routev1.Route, error) {
	route, err := c.route.Get(targetName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return c.route.Create(defaultRoute())
	}
	if err != nil {
		return nil, err
	}
	if len(route.Spec.Host) == 0 {
		return nil, fmt.Errorf("route has no host: %#v", route)
	}
	// TODO make sure route is correct
	return route, nil
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
				TargetPort: intstr.FromInt(443),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationReencrypt,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
		},
	}
}
