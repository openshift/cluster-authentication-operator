package ingressstate

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestSubsetWithReadyAddresses(t *testing.T) {
	objMeta := metav1.ObjectMeta{
		UID: "foo-uid",
	}
	testCases := map[string]struct {
		endpoints   *corev1.Endpoints
		degraded    bool
		errExpected bool
	}{
		"Degraded for missing endpoints": {
			degraded: true,
		},
		"Degraded for empty endpoints": {
			endpoints: &corev1.Endpoints{},
			degraded:  true,
		},
		"Degraded for no subsets": {
			endpoints: &corev1.Endpoints{
				ObjectMeta: objMeta,
			},
			degraded: true,
		},
		"Error if more than one subset": {
			endpoints: &corev1.Endpoints{
				ObjectMeta: objMeta,
				Subsets: []corev1.EndpointSubset{
					{},
					{},
				},
			},
			errExpected: true,
		},
		"Degraded if all addresses are not ready": {
			endpoints: &corev1.Endpoints{
				ObjectMeta: objMeta,
				Subsets: []corev1.EndpointSubset{
					{
						NotReadyAddresses: []corev1.EndpointAddress{
							{IP: "127.0.0.1"},
						},
					},
				},
			},
			degraded: true,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			subset, condition, err := subsetWithReadyAddresses(tc.endpoints)
			if tc.errExpected {
				require.Error(t, err)
				// An error precludes further validation
				return
			} else {
				require.NoError(t, err)
			}
			if tc.degraded {
				require.Nil(t, subset)
				require.NotNil(t, condition)
				require.True(t, degradedConditionTypes.Has(condition.Type))
			} else {
				require.NotNil(t, subset)
				require.Nil(t, condition)
				require.Equal(t, &tc.endpoints.Subsets[0], subset)
			}

		})
	}
}

func TestCheckAddresses(t *testing.T) {
	testCases := map[string]struct {
		addresses          []corev1.EndpointAddress
		unhealthyEndpoints []string
		unhealthyPods      []string
		conditionCount     int
	}{
		"Healthy with 1 unhealthy endpoint": {
			addresses: []corev1.EndpointAddress{
				{IP: "127.0.0.1"},
			},
			unhealthyEndpoints: []string{"127.0.0.1"},
		},
		"Degraded with 2 unhealthy endpoints": {
			addresses: []corev1.EndpointAddress{
				{IP: "127.0.0.1"},
				{IP: "127.0.0.2"},
			},
			unhealthyEndpoints: []string{"127.0.0.1", "127.0.0.2"},
			conditionCount:     1,
		},
		"Healthy with 1 unhealthy pod": {
			addresses: []corev1.EndpointAddress{
				{
					TargetRef: &corev1.ObjectReference{
						Kind: "Pod",
						Name: "foo",
					},
				},
			},
			unhealthyPods: []string{"foo"},
		},
		"Degraded with 2 unhealthy pods": {
			addresses: []corev1.EndpointAddress{
				{
					TargetRef: &corev1.ObjectReference{
						Kind: "Pod",
						Name: "foo",
					},
				},
				{
					TargetRef: &corev1.ObjectReference{
						Kind: "Pod",
						Name: "bar",
					},
				},
			},
			unhealthyPods:  []string{"foo", "bar"},
			conditionCount: 1,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			unhealthyEndpoints := sets.NewString(tc.unhealthyEndpoints...)
			unhealthyPods := sets.NewString(tc.unhealthyPods...)
			conditions := checkAddresses(
				context.TODO(),
				tc.addresses,
				func(_ context.Context, reference *corev1.ObjectReference) []string {
					if unhealthyPods.Has(reference.Name) {
						return []string{"unhealthy"}
					}
					return nil
				},
				func(endpointIP string) error {
					if unhealthyEndpoints.Has(endpointIP) {
						return fmt.Errorf("unhealthy")
					}
					return nil
				},
			)
			for _, condition := range conditions {
				require.True(t, degradedConditionTypes.Has(condition.Type))
			}
			if tc.conditionCount != len(conditions) {
				t.Fatalf("expected %d degraded conditions, got %d", tc.conditionCount, len(conditions))
			}
		})
	}
}
