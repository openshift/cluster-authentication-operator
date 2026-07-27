package switchedcontroller

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestSwitchedControllerSwitchedOnWithNoExistingContext(t *testing.T) {
	started := make(chan struct{})
	var startHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
		started <- struct{}{}
		return nil
	}

	delegateFn := func(_ context.Context) *factory.Factory {
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return nil
			}).WithPostStartHooks(startHook)
	}

	// just always switch on
	switchFn := func() (bool, error) {
		return true, nil
	}

	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		false,
	)

	err := switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	timeoutCtx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	select {
	case <-timeoutCtx.Done():
		t.Fatal("timed out waiting for delegate controller to be started")
	case <-started:
		break
	}
}

func TestSwitchedControllerSwitchedOnWithExistingCanceledContext(t *testing.T) {
	started := make(chan struct{})
	var startHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
		started <- struct{}{}
		return nil
	}

	delegateFn := func(_ context.Context) *factory.Factory {
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return nil
			}).WithPostStartHooks(startHook)
	}

	// just always switch on
	switchFn := func() (bool, error) {
		return true, nil
	}

	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		false,
	)

	// First, start a delegate controller so we can cancel its context and trigger another sync
	// with a new context to verify it starts another delegate controller

	canceledCtx, cancel := context.WithCancel(t.Context())
	err := switched.Sync(canceledCtx, factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	firstTimeoutCtx, firstTimeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer firstTimeoutCancel()

	select {
	case <-firstTimeoutCtx.Done():
		t.Fatal("timed out waiting for first delegate controller to be started")
	case <-started:
		break
	}

	// Now trigger the second sync after externally cancelling the original context
	cancel()
	err = switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer timeoutCancel()

	select {
	case <-timeoutCtx.Done():
		t.Fatal("timed out waiting for second delegate controller to be started")
	case <-started:
		break
	}
}

func TestSwitchedControllerSwitchedOnWithExistingContext(t *testing.T) {
	started := make(chan struct{})
	var startHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
		started <- struct{}{}
		return nil
	}

	delegateCount := 0
	delegateFn := func(_ context.Context) *factory.Factory {
		delegateCount += 1
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return nil
			}).WithPostStartHooks(startHook)
	}

	// just always switch on
	switchFn := func() (bool, error) {
		return true, nil
	}

	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		false,
	)

	// Start a delegate controller on the first sync
	err := switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	firstTimeoutCtx, firstTimeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer firstTimeoutCancel()

	select {
	case <-firstTimeoutCtx.Done():
		t.Fatal("timed out waiting for first delegate controller to be started")
	case <-started:
		break
	}

	// Trigger a second sync
	err = switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// Because a delegate controller is already running, it shouldn't
	// have called the delegate function again
	if delegateCount > 1 {
		t.Fatalf("expected a single call to the delegateFn, but it was called %d times.", delegateCount)
	}
}

func TestSwitchedControllerSwitchedOffWithExistingCanceledContext(t *testing.T) {
	started := make(chan struct{})
	var startHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
		started <- struct{}{}
		return nil
	}

	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))
	originalSyncContext := factory.NewSyncContext("test-sync", recorder)

	delegateCount := 0
	delegateFn := func(_ context.Context) *factory.Factory {
		delegateCount += 1
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return nil
			}).WithPostStartHooks(startHook).WithSyncContext(originalSyncContext)
	}

	switchOn := true
	switchFn := func() (bool, error) {
		return switchOn, nil
	}

	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		false,
	)

	// First, start a delegate controller so we can cancel its context and trigger another sync
	// where we tell the switched controller we should shut the delegate controller off.

	canceledCtx, cancel := context.WithCancel(t.Context())
	err := switched.Sync(canceledCtx, originalSyncContext)
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	firstTimeoutCtx, firstTimeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer firstTimeoutCancel()

	select {
	case <-firstTimeoutCtx.Done():
		t.Fatal("timed out waiting for delegate controller to be started")
	case <-started:
		break
	}

	// Now trigger the second sync after externally cancelling the original context
	// and telling it that it should shut the delegate controller down

	cancel()
	switchOn = false
	err = switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// Because we are switching off, we shouldn't
	// have called the delegate function again
	if delegateCount > 1 {
		t.Fatalf("expected a single call to the delegateFn, but it was called %d times.", delegateCount)
	}

	// It shouldn't take the delgate controller very long to shut down
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second for the controller queue to start shutting down
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer timeoutCancel()

	for {
		select {
		case <-timeoutCtx.Done():
			t.Fatal("timed out waiting for delegate controller to shutdown")
		default:
			if originalSyncContext.Queue().ShuttingDown() {
				return
			}
		}
	}
}

func TestSwitchedControllerSwitchedOffWithExistingContext(t *testing.T) {
	started := make(chan struct{})
	var startHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
		started <- struct{}{}
		return nil
	}

	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))
	originalSyncContext := factory.NewSyncContext("test-sync", recorder)

	delegateCount := 0
	delegateFn := func(_ context.Context) *factory.Factory {
		delegateCount += 1
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return nil
			}).WithPostStartHooks(startHook).WithSyncContext(originalSyncContext)
	}

	switchOn := true
	switchFn := func() (bool, error) {
		return switchOn, nil
	}

	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		false,
	)

	// First, start a delegate controller so we can we tell the switched controller we should shut the delegate controller off.

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := switched.Sync(ctx, originalSyncContext)
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// It shouldn't take the delgate controller very long to start up
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second to start up
	firstTimeoutCtx, firstTimeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer firstTimeoutCancel()

	select {
	case <-firstTimeoutCtx.Done():
		t.Fatal("timed out waiting for delegate controller to be started")
	case <-started:
		break
	}

	// Now trigger the second sync after externally cancelling the original context
	// and telling it that it should shut the delegate controller down
	switchOn = false
	err = switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// Because we are switching off, we shouldn't
	// have called the delegate function again
	if delegateCount > 1 {
		t.Fatalf("expected a single call to the delegateFn, but it was called %d times.", delegateCount)
	}

	// It shouldn't take the delgate controller very long to shut down
	// but because it is inherently an asynchronous process we fail if it takes
	// longer than half a second for the controller queue to start shutting down
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer timeoutCancel()

	for {
		select {
		case <-timeoutCtx.Done():
			t.Fatal("timed out waiting for delegate controller to shutdown")
		default:
			if originalSyncContext.Queue().ShuttingDown() {
				return
			}
		}
	}
}

type applyStatusCall struct {
	fieldManager       string
	applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration
}

// synchronizedOperatorClient serializes access to a non-thread-safe OperatorClient
// (e.g. fakeOperatorClient) so it can be used safely from multiple goroutines.
type synchronizedOperatorClient struct {
	v1helpers.OperatorClient
	mu            sync.Mutex
	statusApplied chan struct{}
}

func (c *synchronizedOperatorClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) error {
	c.mu.Lock()
	err := c.OperatorClient.ApplyOperatorStatus(ctx, fieldManager, applyConfiguration)
	c.mu.Unlock()
	if c.statusApplied != nil {
		select {
		case c.statusApplied <- struct{}{}:
		default:
		}
	}
	return err
}

type recordingOperatorClient struct {
	v1helpers.OperatorClient
	applyStatusCalls []applyStatusCall
}

func (r *recordingOperatorClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) error {
	r.applyStatusCalls = append(r.applyStatusCalls, applyStatusCall{fieldManager: fieldManager, applyConfiguration: applyConfiguration})
	return r.OperatorClient.ApplyOperatorStatus(ctx, fieldManager, applyConfiguration)
}

func TestSwitchedControllerClearsDelegateConditionsOnSwitchOff(t *testing.T) {
	recorder := events.NewInMemoryRecorder("switchedcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))
	fakeClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
	syncClient := &synchronizedOperatorClient{
		OperatorClient: fakeClient,
		statusApplied:  make(chan struct{}, 1),
	}
	operatorClient := &recordingOperatorClient{OperatorClient: syncClient}

	delegateFn := func(_ context.Context) *factory.Factory {
		var enqueueSyncHook factory.PostStartHook = func(ctx context.Context, syncContext factory.SyncContext) error {
			syncContext.Queue().Add("key")
			return nil
		}
		return factory.New().
			WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
				return fmt.Errorf("route.route.openshift.io \"oauth-openshift\" not found")
			}).
			WithSyncDegradedOnError(syncClient).
			WithPostStartHooks(enqueueSyncHook)
	}

	switchOn := true
	switchFn := func() (bool, error) {
		return switchOn, nil
	}

	switched := NewControllerWithSwitch(
		operatorClient,
		"test-controller",
		delegateFn,
		switchFn,
		nil,
		time.Hour,
		recorder,
		true,
	)

	// Start the delegate
	err := switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing: %v", err)
	}

	// Wait for the delegate's reportDegraded to call ApplyOperatorStatus.
	// This signal fires after reportDegraded completes (not just after sync returns),
	// which avoids a data race on the non-thread-safe fakeOperatorClient.
	syncTimeoutCtx, syncTimeoutCancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer syncTimeoutCancel()

	select {
	case <-syncTimeoutCtx.Done():
		t.Fatal("timed out waiting for delegate controller to report degraded status")
	case <-syncClient.statusApplied:
	}

	// Switch off and sync the wrapper — this should clear delegate conditions
	switchOn = false
	err = switched.Sync(t.Context(), factory.NewSyncContext("test-sync", recorder))
	if err != nil {
		t.Fatalf("unexpected error when syncing after switch off: %v", err)
	}

	// Verify that ApplyOperatorStatus was called with the delegate's field manager
	// and an empty OperatorStatus to clear its conditions.
	// This is the most appropriate way to verify the behavior is working as expected because
	// fake clients do not implement the server-side apply logic for field management, meaning the
	// condition would still be in place.
	expectedFieldManager := factory.ControllerFieldManager("test-controller", "reportDegraded")

	if len(operatorClient.applyStatusCalls) != 1 {
		t.Fatalf("expected a single apply status call to clear degraded conditions from delegate controller syncing but got %d calls", len(operatorClient.applyStatusCalls))
	}

	call := operatorClient.applyStatusCalls[0]

	if call.fieldManager != expectedFieldManager {
		t.Errorf("expected field manager %q but got %q instead", expectedFieldManager, call.fieldManager)
	}

	if len(call.applyConfiguration.Conditions) > 0 {
		t.Errorf("expected empty conditions to be applied but got conditions %v", call.applyConfiguration.Conditions)
	}
}
