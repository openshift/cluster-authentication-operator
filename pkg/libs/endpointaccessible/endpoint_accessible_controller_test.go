package endpointaccessible

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func newSyncContext(t *testing.T) factory.SyncContext {
	t.Helper()
	return factory.NewSyncContext(t.Name(), events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())))
}

func TestEndpointAccessibleController_sync(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okServer.Close()

	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	tests := []struct {
		name                      string
		endpointListFn            EndpointListFunc
		endpointCheckDisabledFunc EndpointCheckDisabledFunc
		wantErr                   bool
	}{
		{
			name: "all endpoints working",
			endpointListFn: func() ([]string, error) {
				return []string{okServer.URL}, nil
			},
		},
		{
			name: "endpoints lister error",
			endpointListFn: func() ([]string, error) {
				return nil, fmt.Errorf("some error")
			},
			wantErr: true,
		},
		{
			name: "non working endpoints",
			endpointListFn: func() ([]string, error) {
				return []string{failServer.URL}, nil
			},
			wantErr: true,
		},
		{
			name: "invalid url",
			endpointListFn: func() ([]string, error) {
				return []string{"htt//bad`string"}, nil
			},
			wantErr: true,
		},
		{
			name: "endpoint check disabled",
			endpointCheckDisabledFunc: func() (bool, error) {
				return true, nil
			},
			wantErr: false,
		},
		{
			name: "endpoint check disabled func returns error",
			endpointCheckDisabledFunc: func() (bool, error) {
				return false, fmt.Errorf("fake error")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c := &endpointAccessibleController{
				operatorClient:            v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
				endpointListFn:            tt.endpointListFn,
				endpointCheckDisabledFunc: tt.endpointCheckDisabledFunc,
				httpClient:                http.DefaultClient,
				attemptCount:              1,
			}
			if err := c.sync(ctx, newSyncContext(t)); (err != nil) != tt.wantErr {
				t.Errorf("sync() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEndpointAccessibleController_sync_retryStaleEndpoint verifies that
// endpointListFn is re-invoked on each retry attempt. This covers the upgrade
// scenario where Endpoints/EndpointSlices briefly contain a stale pod IP: the
// first fetch returns the dead pod, but by the second attempt the object has
// been updated and the fresh pod IP is returned instead.
func TestEndpointAccessibleController_sync_retryStaleEndpoint(t *testing.T) {
	deadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer deadServer.Close()

	freshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer freshServer.Close()

	var listCallCount atomic.Int32
	c := &endpointAccessibleController{
		operatorClient: v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
		endpointListFn: func() ([]string, error) {
			// First call returns the stale (dead) pod IP; subsequent calls
			// return the fresh one, simulating an Endpoints object update.
			if listCallCount.Add(1) == 1 {
				return []string{deadServer.URL}, nil
			}
			return []string{freshServer.URL}, nil
		},
		httpClient:    http.DefaultClient,
		attemptCount:  3,
		retryInterval: time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.sync(ctx, newSyncContext(t)); err != nil {
		t.Errorf("sync() unexpected error: %v", err)
	}
	if n := listCallCount.Load(); n != 2 {
		t.Errorf("endpointListFn called %d times, want 2", n)
	}
}

