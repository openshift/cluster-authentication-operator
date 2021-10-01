package common

import (
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
)

func GetOAuthServerRoute(routeLister routev1lister.RouteLister, conditionPrefix string) (*routev1.Route, []operatorv1.OperatorCondition) {
	route, err := routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, []operatorv1.OperatorCondition{{
				Type:    conditionPrefix + "Degraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "NotFound",
				Message: "The OAuth server route 'openshift-authentication/oauth-openshift' was not found",
			}}
		}

		return nil, []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Degraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get 'openshift-authentication/oauth-openshift' route: %v", err),
			},
		}
	}
	return route, nil
}
