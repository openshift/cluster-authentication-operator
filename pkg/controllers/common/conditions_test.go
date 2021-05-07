package common

import (
	"fmt"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const controllerName = "TestController"

func TestControllerProgressingErrorIsDegraded(t *testing.T) {
	tests := []struct {
		name               string
		reason             string
		err                error
		maxAge             time.Duration
		previousConditions []operatorv1.OperatorCondition
		expectedDegraded   bool
	}{
		{
			name:               "no previous condition",
			reason:             "TestReason",
			err:                fmt.Errorf("working on this"),
			maxAge:             5 * time.Minute,
			previousConditions: []operatorv1.OperatorCondition{},
		},
		{
			name:   "different previous progressing condition",
			reason: "TestReason",
			err:    fmt.Errorf("working on this"),
			maxAge: 5 * time.Minute,
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               "SomethingElseIsProgressing",
					Status:             operatorv1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-6 * time.Minute)),
					Message:            "things are happening",
				},
			},
		},
		{
			name:   "previous condition but within time limit",
			reason: "TestReason",
			err:    fmt.Errorf("working on this"),
			maxAge: 5 * time.Minute,
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               ControllerProgressingConditionName(controllerName),
					Status:             operatorv1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-4 * time.Minute)),
					Reason:             "TestReason",
					Message:            "working on this",
				},
			},
		},
		{
			name:   "previous condition outside time limit",
			reason: "TestReason",
			err:    fmt.Errorf("working on this"),
			maxAge: 5 * time.Minute,
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               ControllerProgressingConditionName(controllerName),
					Status:             operatorv1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-6 * time.Minute)),
					Reason:             "TestReason",
					Message:            "working on this",
				},
			},
			expectedDegraded: true,
		},
		{
			name:   "previous condition outside time limit but with a different message",
			reason: "TestReason",
			err:    fmt.Errorf("working on this"),
			maxAge: 5 * time.Minute,
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               ControllerProgressingConditionName(controllerName),
					Status:             operatorv1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-6 * time.Minute)),
					Reason:             "TestReason",
					Message:            "working on this but differently",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ControllerProgressingError{
				reason: tt.reason,
				err:    tt.err,
				maxAge: tt.maxAge,
			}
			if got := e.IsDegraded(controllerName, &operatorv1.OperatorStatus{Conditions: tt.previousConditions}); got != tt.expectedDegraded {
				t.Errorf("ControllerProgressingError.IsDegraded() = %v, expectedDegraded %v", got, tt.expectedDegraded)
			}
		})
	}
}
