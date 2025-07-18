package switchedcontroller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/sets"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestSwitchedController(t *testing.T) {
	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))

	i := 0
	var mutex sync.Mutex
	expectedRuns := sets.New[int](1, 2, 5)
	actualRuns := sets.New[int]()

	delegateFn := func(_ context.Context) *factory.Factory {
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				mutex.Lock()
				defer mutex.Unlock()
				actualRuns.Insert(i)
				return nil
			}).
			ResyncEvery(65 * time.Second)
	}

	switchFn := func() (bool, error) {
		mutex.Lock()
		defer mutex.Unlock()
		i += 1
		return expectedRuns.Has(i), nil
	}

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		1*time.Minute,
		recorder,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	go switched.Run(ctx, 1)
	<-ctx.Done()

	require.Equal(t, i, 6)
	require.True(t, actualRuns.Equal(expectedRuns), fmt.Sprintf("wanted: %v; got: %v", expectedRuns, actualRuns))
}
