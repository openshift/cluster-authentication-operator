package ingressstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

func readyEndpoint(ready bool) common.ServiceEndpoint {
	return common.ServiceEndpoint{Address: "127.0.0.1", Ready: ready}
}

func TestReadyAddressesOrDegraded(t *testing.T) {
	testCases := map[string]struct {
		sliceCount   int
		endpoints    []common.ServiceEndpoint
		degraded     bool
		wantReadyLen int
	}{
		"Degraded for missing endpointslices": {
			sliceCount: 0,
			degraded:   true,
		},
		"Degraded for no endpoints in slices": {
			sliceCount: 1,
			endpoints:  nil,
			degraded:   true,
		},
		"Degraded if all addresses are not ready": {
			sliceCount: 1,
			endpoints:  []common.ServiceEndpoint{readyEndpoint(false)},
			degraded:   true,
		},
		"Ready addresses returned": {
			sliceCount:   1,
			endpoints:    []common.ServiceEndpoint{readyEndpoint(true), readyEndpoint(false)},
			wantReadyLen: 1,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			ready, condition := readyAddressesOrDegraded(tc.sliceCount, tc.endpoints)
			if tc.degraded {
				require.Nil(t, ready)
				require.NotNil(t, condition)
				require.True(t, degradedConditionTypes.Has(condition.Type))
			} else {
				require.Nil(t, condition)
				require.Len(t, ready, tc.wantReadyLen)
			}
		})
	}
}

func TestCheckAddresses(t *testing.T) {
	testCases := map[string]struct {
		addresses      []common.ServiceEndpoint
		unhealthyPods  []string
		conditionCount int
	}{
		"Healthy with 1 unhealthy pod": {
			addresses: []common.ServiceEndpoint{
				{
					TargetRef: &corev1.ObjectReference{
						Kind: "Pod",
						Name: "foo",
					},
				},
			},
			unhealthyPods:  []string{"foo"},
			conditionCount: 1,
		},
		"Degraded with 2 unhealthy pods": {
			addresses: []common.ServiceEndpoint{
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
