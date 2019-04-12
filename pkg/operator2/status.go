package operator2

import (
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func setFailingTrue(operatorConfig *operatorv1.Authentication, reason, message string) {
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions,
		operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeFailing,
			Status:  operatorv1.ConditionTrue,
			Reason:  reason,
			Message: message,
		})
}

func setFailingFalse(operatorConfig *operatorv1.Authentication) {
	v1helpers.SetOperatorCondition(&operatorConfig.Status.Conditions,
		operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeFailing,
			Status: operatorv1.ConditionFalse,
		})
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
