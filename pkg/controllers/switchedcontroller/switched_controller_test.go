package switchedcontroller

import (
	"context"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
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
