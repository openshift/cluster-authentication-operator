package common

import (
	"context"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var _ error = &ControllerProgressingError{}

type ControllerProgressingError struct {
	reason string
	err    error
	maxAge time.Duration
}

// NewControllerProgressingError creates a ControllerProgressingError that can be
// handled by the controllers in a generic manner to go Progressing instead of Degraded.
// The error allows configuring `maxAge` which determines for how long can an
// this error appear in the operator's status before it goes Degraded:
// maxAge:
//   <= 0 - never go Degraded
//   > 0  - go Degraded if the controller was progressing with this error longer than `maxAge`
func NewControllerProgressingError(reason string, err error, maxAge time.Duration) *ControllerProgressingError {
	return &ControllerProgressingError{
		reason: reason,
		err:    err,
		maxAge: maxAge,
	}
}

func (e *ControllerProgressingError) Error() string {
	return e.err.Error()
}

func (e *ControllerProgressingError) Unwrap() error {
	return e.err
}

func (e *ControllerProgressingError) ToCondition(controllerName string) operatorv1.OperatorCondition {
	return operatorv1.OperatorCondition{
		Type:    ControllerProgressingConditionName(controllerName),
		Status:  operatorv1.ConditionTrue,
		Reason:  e.reason,
		Message: e.err.Error(),
	}
}

// IsDegraded returns true if the condition matching this error (same type, reason and message)
// was found in the previous operator status and its `lastTransitionTime` appeared
// longer than `maxAge` ago
func (e *ControllerProgressingError) IsDegraded(controllerName string, lastStatus *operatorv1.OperatorStatus) bool {
	if e.maxAge <= 0 {
		return false
	}

	lastCondition := v1helpers.FindOperatorCondition(lastStatus.Conditions, ControllerProgressingConditionName(controllerName))
	if lastCondition == nil {
		return false
	}

	if lastCondition.Reason != e.reason || lastCondition.Message != e.Error() {
		return false
	}

	if lastTransition := lastCondition.LastTransitionTime; !lastTransition.IsZero() {
		return lastTransition.Add(e.maxAge).Before(time.Now())
	}
	return false
}

func ControllerProgressingConditionName(controllerName string) string {
	return controllerName + "Progressing"
}

func UpdateControllerConditions(ctx context.Context, operatorClient v1helpers.OperatorClient, allConditionNames sets.String, updatedConditions []operatorv1.OperatorCondition) error {
	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}

	for _, conditionType := range allConditionNames.List() {
		// clean up existing updatedConditions
		newCondition := operatorv1.OperatorCondition{
			Type:   conditionType,
			Status: operatorv1.ConditionFalse,
		}
		if strings.HasSuffix(conditionType, "Available") {
			newCondition.Status = operatorv1.ConditionTrue
		}

		if condition := v1helpers.FindOperatorCondition(updatedConditions, conditionType); condition != nil {
			newCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(newCondition))
	}

	if _, _, err := v1helpers.UpdateStatus(ctx, operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	return nil
}
