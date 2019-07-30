package operator2

import (
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func handleDegraded(operatorConfig *operatorv1.Authentication, prefix string, err error) {
	if err != nil {
		v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions,
			operatorv1.OperatorCondition{
				Type:    prefix + operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "Error",
				Message: err.Error(),
			})
		return
	}
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions,
		operatorv1.OperatorCondition{
			Type:   prefix + operatorv1.OperatorStatusTypeDegraded,
			Status: operatorv1.ConditionFalse,
		})
}

func isDegraded(operatorConfig *operatorv1.Authentication) bool {
	for _, condition := range operatorConfig.Status.Conditions {
		if strings.HasSuffix(condition.Type, operatorv1.OperatorStatusTypeDegraded) &&
			condition.Status == operatorv1.ConditionTrue {
			return true
		}
	}
	return false
}

func setProgressingTrue(operatorConfig *operatorv1.Authentication, reason, message string) {
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions, operatorv1.OperatorCondition{
		Type:    operatorv1.OperatorStatusTypeProgressing,
		Status:  operatorv1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
}

func setAvailableTrue(operatorConfig *operatorv1.Authentication, reason string) {
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeAvailable,
		Status: operatorv1.ConditionTrue,
		Reason: reason,
	})
}

func setProgressingFalse(operatorConfig *operatorv1.Authentication) {
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeProgressing,
		Status: operatorv1.ConditionFalse,
	})
}

func setProgressingTrueAndAvailableFalse(operatorConfig *operatorv1.Authentication, reason, message string) {
	setProgressingTrue(operatorConfig, reason, message)

	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeAvailable,
		Status: operatorv1.ConditionFalse,
	})
}
