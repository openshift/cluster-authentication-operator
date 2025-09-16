package deployment

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestSetRollingUpdateParameters(t *testing.T) {
	testCases := []struct {
		name                   string
		controlPlaneCount      int32
		expectedMaxUnavailable int32
		expectedMaxSurge       int32
	}{
		{
			name:                   "single control plane node",
			controlPlaneCount:      1,
			expectedMaxUnavailable: 1, // max(1-1, 1) = max(0, 1) = 1
			expectedMaxSurge:       1,
		},
		{
			name:                   "two control plane nodes",
			controlPlaneCount:      2,
			expectedMaxUnavailable: 1, // max(2-1, 1) = max(1, 1) = 1
			expectedMaxSurge:       2,
		},
		{
			name:                   "three control plane nodes",
			controlPlaneCount:      3,
			expectedMaxUnavailable: 2, // max(3-1, 1) = max(2, 1) = 2
			expectedMaxSurge:       3,
		},
		{
			name:                   "four control plane nodes",
			controlPlaneCount:      4,
			expectedMaxUnavailable: 3, // max(4-1, 1) = max(3, 1) = 3
			expectedMaxSurge:       4,
		},
		{
			name:                   "five control plane nodes",
			controlPlaneCount:      5,
			expectedMaxUnavailable: 4, // max(5-1, 1) = max(4, 1) = 4
			expectedMaxSurge:       5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test deployment with rolling update strategy
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "test-namespace",
				},
				Spec: appsv1.DeploymentSpec{
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RollingUpdateDeploymentStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDeployment{
							MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
							MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
						},
					},
				},
			}

			// Call the function under test
			setRollingUpdateParameters(tc.controlPlaneCount, deployment)

			// Verify MaxUnavailable is set correctly
			if deployment.Spec.Strategy.RollingUpdate.MaxUnavailable == nil {
				t.Errorf("MaxUnavailable should not be nil")
			} else {
				actualMaxUnavailable := deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal
				if actualMaxUnavailable != tc.expectedMaxUnavailable {
					t.Errorf("Expected MaxUnavailable to be %d, got %d", tc.expectedMaxUnavailable, actualMaxUnavailable)
				}
			}

			// Verify MaxSurge is set correctly
			if deployment.Spec.Strategy.RollingUpdate.MaxSurge == nil {
				t.Errorf("MaxSurge should not be nil")
			} else {
				actualMaxSurge := deployment.Spec.Strategy.RollingUpdate.MaxSurge.IntVal
				if actualMaxSurge != tc.expectedMaxSurge {
					t.Errorf("Expected MaxSurge to be %d, got %d", tc.expectedMaxSurge, actualMaxSurge)
				}
			}

			// Verify the values are of type Int (not String)
			if deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.Type != intstr.Int {
				t.Errorf("Expected MaxUnavailable to be of type Int, got %v", deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.Type)
			}
			if deployment.Spec.Strategy.RollingUpdate.MaxSurge.Type != intstr.Int {
				t.Errorf("Expected MaxSurge to be of type Int, got %v", deployment.Spec.Strategy.RollingUpdate.MaxSurge.Type)
			}
		})
	}
}
