package common

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
)

func GetIngressConfig(ingressLister configv1lister.IngressLister, conditionPrefix string) (*configv1.Ingress, []operatorv1.OperatorCondition) {
	ingress, err := ingressLister.Get("cluster")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    conditionPrefix + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotFound",
			Message: fmt.Sprintf("Unable to get cluster ingress config: %v", err),
		}}
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, []operatorv1.OperatorCondition{{
			Type:    conditionPrefix + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return ingress, nil
}
