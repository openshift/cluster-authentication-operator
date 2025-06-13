package oauthclientsswitchedinformer

import (
	"context"
	"fmt"
	"testing"
	"time"

	oauthv1 "github.com/openshift/api/oauth/v1"
	fakeoauthclient "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	oauthinformers "github.com/openshift/client-go/oauth/informers/externalversions"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/util/wait"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestSync(t *testing.T) {
	testCtx, testCancel := context.WithCancel(context.TODO())
	defer testCancel()

	testOAuthClient := &oauthv1.OAuthClient{}
	testClient := fakeoauthclient.NewSimpleClientset(testOAuthClient)
	testInformer := oauthinformers.NewSharedInformerFactory(testClient, 0).Oauth().V1().OAuthClients()

	var makeItStop bool
	var shouldStopFnErr error
	shouldStopFn := func() (bool, error) {
		return makeItStop, shouldStopFnErr
	}

	informerSwitch := NewSwitchedInformer(
		"TestInformerWithSwitchController",
		testCtx,
		shouldStopFn,
		testInformer,
		0,
		nil,
		events.NewInMemoryRecorder("oauthclientscontroller_test", clocktesting.NewFakePassiveClock(time.Now())),
	)

	t.Run("start informer", func(tt *testing.T) {
		makeItStop = false
		shouldStopFnErr = nil
		err := informerSwitch.sync(testCtx, nil)
		if err != nil {
			tt.Errorf("unexpected sync error: %v", err)
		}
		waitForInformerSynced(tt, testCtx, informerSwitch)

		// informer should be running

		if informerSwitch.runCtx == nil {
			tt.Error("EnsureRunning: runCtx is nil when it should be non-nil")
		}

		if informerSwitch.stopFunc == nil {
			tt.Error("EnsureRunning: stopFunc is nil when it should be non-nil")
		}

		if informerSwitch.Informer().IsStopped() {
			tt.Error("EnsureRunning: informer is stopped when it should be started")
		}
	})

	t.Run("stop informer with error", func(tt *testing.T) {
		makeItStop = true
		shouldStopFnErr = fmt.Errorf("stop fails")
		err := informerSwitch.sync(testCtx, nil)
		if err == nil {
			tt.Errorf("got no error while expecting one")
		}
		waitForInformerSynced(tt, testCtx, informerSwitch)

		// informer should still be running

		if informerSwitch.runCtx == nil {
			tt.Error("EnsureRunning: runCtx is nil when it should be non-nil")
		}

		if informerSwitch.stopFunc == nil {
			tt.Error("EnsureRunning: stopFunc is nil when it should be non-nil")
		}

		if informerSwitch.Informer().IsStopped() {
			tt.Error("EnsureRunning: informer is stopped when it should be started")
		}

	})

	t.Run("stop informer without error", func(tt *testing.T) {
		makeItStop = true
		shouldStopFnErr = nil
		err := informerSwitch.sync(testCtx, nil)
		if err != nil {
			tt.Errorf("unexpected sync error: %v", err)
		}
		waitForInformerStopped(tt, testCtx, informerSwitch)

		// informer should stop

		if informerSwitch.runCtx != nil {
			tt.Error("Stop: runCtx is not nil when it should be nil")
		}

		if informerSwitch.stopFunc != nil {
			tt.Error("Stop: stopFunc is not nil when it should be nil")
		}

		if !informerSwitch.Informer().IsStopped() {
			tt.Error("Stop: informer is started when it should be stopped")
		}
	})
}

func waitForInformerSynced(t *testing.T, ctx context.Context, informerSwitch *InformerWithSwitch) {
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 1*time.Second, true, func(ctx context.Context) (done bool, err error) {
		return informerSwitch.Informer().HasSynced(), nil
	})
	if err != nil {
		t.Fatalf("unexpected error while waiting for informer to sync: %v", err)
	}
}

func waitForInformerStopped(t *testing.T, ctx context.Context, informerSwitch *InformerWithSwitch) {
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 1*time.Second, true, func(ctx context.Context) (done bool, err error) {
		return informerSwitch.Informer().IsStopped(), nil
	})
	if err != nil {
		t.Fatalf("unexpected error while waiting for informer to stop: %v", err)
	}
}
