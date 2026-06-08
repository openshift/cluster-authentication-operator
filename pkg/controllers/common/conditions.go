package common

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

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
