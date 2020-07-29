package common

import (
	"fmt"
	"os"

	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"

	corev1 "k8s.io/api/core/v1"
)

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

func RouteHasCanonicalHost(route *routev1.Route, canonicalHost string) bool {
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
