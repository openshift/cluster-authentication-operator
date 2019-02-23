package operator2

import (
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func (c *authOperator) setFailingStatus(operatorConfig *operatorv1.Authentication, reason, message string) error {
	failStatusFunc := func(status *operatorv1.OperatorStatus) error {
		v1helpers.SetOperatorCondition(&status.Conditions,
			operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeFailing,
				Status:  operatorv1.ConditionTrue,
				Reason:  reason,
				Message: message,
			})

		v1helpers.SetOperatorCondition(&status.Conditions, operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeProgressing,
			Status: operatorv1.ConditionFalse,
		})

		v1helpers.SetOperatorCondition(&status.Conditions,
			operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeAvailable,
				Status: operatorv1.ConditionFalse,
			})

		return nil
	}

	_, _, err := v1helpers.UpdateStatus(c.authOperatorConfigClient, failStatusFunc)
	return err
}

func (c *authOperator) setAvailableStatus(operatorConfig *operatorv1.Authentication) error {
	availStatusFunc := func(status *operatorv1.OperatorStatus) error {
		v1helpers.SetOperatorCondition(&status.Conditions, operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeAvailable,
			Status: operatorv1.ConditionTrue,
		})

		v1helpers.SetOperatorCondition(&status.Conditions, operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeProgressing,
			Status: operatorv1.ConditionFalse,
		})

		v1helpers.SetOperatorCondition(&status.Conditions, operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeFailing,
			Status: operatorv1.ConditionFalse,
		})

		return nil
	}

	_, _, err := v1helpers.UpdateStatus(c.authOperatorConfigClient, availStatusFunc)
	return err
}
