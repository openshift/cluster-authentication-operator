package readiness

import (
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type ControllerDegradationObservedError struct {
	reason string
	err    error
	maxAge time.Duration
}

func NewControllerDegradationObservedError(reason string, err error, maxAge time.Duration) *ControllerDegradationObservedError {
	return &ControllerDegradationObservedError{
		reason: reason,
		err:    err,
		maxAge: maxAge,
	}
}

func (cdoe *ControllerDegradationObservedError) Error() string {
	return cdoe.err.Error()
}

func (cdoe *ControllerDegradationObservedError) Unwrap() error {
	return cdoe.err
}

func (cdoe *ControllerDegradationObservedError) ToCondition(controllerName string) *applyoperatorv1.OperatorConditionApplyConfiguration {
	return applyoperatorv1.OperatorCondition().
		WithType(ControllerDegradationObservedConditionName(controllerName)).
		WithStatus(operatorv1.ConditionTrue).
		WithReason(cdoe.reason).
		WithMessage(cdoe.err.Error())
}

// IsDegraded returns true if the condition matching this error (same type, reason and message)
// was found in the previous operator status and its `lastTransitionTime` appeared
// longer than `maxAge` ago
func (cdoe *ControllerDegradationObservedError) IsDegraded(controllerName string, lastStatus *operatorv1.OperatorStatus) bool {
	if cdoe.maxAge <= 0 {
		return false
	}

	if lastStatus == nil {
		return false
	}

	lastCondition := v1helpers.FindOperatorCondition(lastStatus.Conditions, ControllerDegradationObservedConditionName(controllerName))
	if lastCondition == nil {
		return false
	}

	if lastCondition.Reason != cdoe.reason || lastCondition.Message != cdoe.Error() {
		return false
	}

	if lastTransition := lastCondition.LastTransitionTime; !lastTransition.IsZero() {
		return lastTransition.Add(cdoe.maxAge).Before(time.Now())
	}
	return false
}

func ControllerDegradationObservedConditionName(controllerName string) string {
	return fmt.Sprintf("%sDegradationObserved", controllerName)
}
