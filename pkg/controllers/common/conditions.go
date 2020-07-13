package common

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func UpdateControllerConditions(operatorClient v1helpers.OperatorClient, allConditionNames sets.String, updatedConditions []operatorv1.OperatorCondition) error {
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

	if _, _, err := v1helpers.UpdateStatus(operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	return nil
}
