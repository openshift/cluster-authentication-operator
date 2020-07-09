package common

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
)

// GetAuthConfig retrieves the authentication config or return degraded condition if an error occurred.
func GetAuthConfig(authLister configv1lister.AuthenticationLister, conditionPrefix string) (*configv1.Authentication, []operatorv1.OperatorCondition) {
	operatorConfig, err := authLister.Get("cluster")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Degraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get cluster authentication config: %v", err),
			},
		}
	}
	return operatorConfig, nil
}
