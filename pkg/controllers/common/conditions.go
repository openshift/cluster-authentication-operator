package common

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
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
//
//	<= 0 - never go Degraded
//	> 0  - go Degraded if the controller was progressing with this error longer than `maxAge`
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

func (e *ControllerProgressingError) ToCondition(controllerName string) *applyoperatorv1.OperatorConditionApplyConfiguration {
	return applyoperatorv1.OperatorCondition().
		WithType(ControllerProgressingConditionName(controllerName)).
		WithStatus(operatorv1.ConditionTrue).
		WithReason(e.reason).
		WithMessage(e.err.Error())
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

func ApplyControllerConditions(ctx context.Context, operatorClient v1helpers.OperatorClient, fieldManager string, allConditionNames sets.String, updatedConditions []operatorv1.OperatorCondition) error {
	if allConditionNames.Len() == 0 {
		return nil
	}

	status := applyoperatorv1.OperatorStatus()
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

		status = status.WithConditions(applyoperatorv1.OperatorCondition().
			WithType(newCondition.Type).
			WithStatus(newCondition.Status).
			WithReason(newCondition.Reason).
			WithMessage(newCondition.Message))
	}

	return operatorClient.ApplyOperatorStatus(ctx, fieldManager, status)
}

func DeleteControllerConditions(ctx context.Context, operatorClient v1helpers.OperatorClient, conditionTypes ...string) error {
	if len(conditionTypes) == 0 {
		return nil
	}

	_, operatorStatus, _, err := operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	// TODO replace with the one from library-go/pkg/operator/v1helpers when this PR gets merged: https://github.com/openshift/library-go/pull/1902
	patch := removeConditionsJSONPatch(operatorStatus, conditionTypes)
	if patch == nil || patch.IsEmpty() {
		return nil
	}

	return operatorClient.PatchOperatorStatus(ctx, patch)
}

func removeConditionsJSONPatch(operatorStatus *operatorv1.OperatorStatus, conditionTypesToRemove []string) *jsonpatch.PatchSet {
	if operatorStatus == nil || len(conditionTypesToRemove) == 0 {
		return nil
	}

	jsonPatch := jsonpatch.New()
	var removedCount int
	for i, cond := range operatorStatus.Conditions {
		for _, conditionTypeToRemove := range conditionTypesToRemove {
			if cond.Type != conditionTypeToRemove {
				continue
			}

			removeAtIndex := i - removedCount
			jsonPatch.WithRemove(
				fmt.Sprintf("/status/conditions/%d", removeAtIndex),
				jsonpatch.NewTestCondition(fmt.Sprintf("/status/conditions/%d/type", removeAtIndex), conditionTypeToRemove),
			)
			removedCount++
		}
	}

	return jsonPatch
}
