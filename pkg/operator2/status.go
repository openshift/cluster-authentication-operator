package operator2

import (
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type authConditions struct {
	conditions  []operatorv1.OperatorCondition
	hasDegraded bool
}

func newAuthConditions() *authConditions {
	return &authConditions{
		conditions: []operatorv1.OperatorCondition{},
	}
}

func (c *authConditions) handleDegraded(prefix string, err error) {
	c.handleDegradedWithReason(prefix, err, "Error")
}

func (c *authConditions) handleDegradedWithReason(prefix string, err error, reason string) {
	if err != nil {
		c.hasDegraded = true
		v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
			Type:    prefix + operatorv1.OperatorStatusTypeDegraded,
			Status:  operatorv1.ConditionTrue,
			Reason:  reason,
			Message: err.Error(),
		})
		return
	}
	v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
		Type:   prefix + operatorv1.OperatorStatusTypeDegraded,
		Status: operatorv1.ConditionFalse,
	})
}

func (c *authConditions) setProgressingTrue(reason, message string) {
	v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
		Type:    operatorv1.OperatorStatusTypeProgressing,
		Status:  operatorv1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
}

func (c *authConditions) setAvailableTrue(reason string) {
	v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeAvailable,
		Status: operatorv1.ConditionTrue,
		Reason: reason,
	})
}

func (c *authConditions) setProgressingFalse() {
	v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeProgressing,
		Status: operatorv1.ConditionFalse,
	})
}

func (c *authConditions) setProgressingTrueAndAvailableFalse(reason, message string) {
	c.setProgressingTrue(reason, message)
	v1helpers.SetOperatorCondition(&c.conditions, operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeAvailable,
		Status: operatorv1.ConditionFalse,
	})
}
