package endpointaccessible

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
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
		httpClient                *http.Client
		wantErr                   bool
	}{
		{
			name: "all endpoints working",
			endpointListFn: func() ([]string, error) {
				return []string{okServer.URL}, nil
			},
			httpClient: okServer.Client(),
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
			httpClient: failServer.Client(),
			wantErr:    true,
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
				httpClient:                tt.httpClient,
				attemptCount:              1,
			}
			if err := c.sync(ctx, newSyncContext(t)); (err != nil) != tt.wantErr {
				t.Errorf("sync() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEndpointAccessibleController_sync_retry verifies the retry logic.
func TestEndpointAccessibleController_sync_retry(t *testing.T) {
	tests := []struct {
		name       string
		failFirstN int // how many initial requests the server should reject with 500
		wantErr    bool
	}{
		{
			name:       "succeeds on last attempt",
			failFirstN: 2,
			wantErr:    false,
		},
		{
			name:       "fails after all attempts exhausted",
			failFirstN: 3,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var requestCount atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if int(requestCount.Add(1)) <= tt.failFirstN {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			c := &endpointAccessibleController{
				operatorClient: v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
				endpointListFn: func() ([]string, error) {
					return []string{server.URL}, nil
				},
				httpClient:    server.Client(),
				retryInterval: time.Millisecond,
				attemptCount:  3,
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
		httpClient:    deadServer.Client(), // plain HTTP, works for both servers
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

// TestEndpointAccessibleController_sync_requestTimeout verifies that the
// per-request timeout is enforced and that the retry mechanism handles
// timed-out requests correctly. synctest controls fake time so the test
// runs instantly.
func TestEndpointAccessibleController_sync_requestTimeout(t *testing.T) {
	tests := []struct {
		name      string
		hangCount int32 // requests that time out before one succeeds
		wantErr   bool
	}{
		{
			name:      "succeeds after one timed-out retry",
			hangCount: 1,
			wantErr:   false,
		},
		{
			name:      "fails after all retries time out",
			hangCount: 3,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the sync context outside the bubble: factory.NewSyncContext spawns
			// a background work-queue goroutine that never exits on its own, which would
			// deadlock the synctest bubble.
			syncCtx := newSyncContext(t)
			synctest.Test(t, func(t *testing.T) {
				c := &endpointAccessibleController{
					operatorClient: v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
					endpointListFn: func() ([]string, error) {
						return []string{"http://example.com"}, nil
					},
					httpClient:     &http.Client{Transport: &hangingTransport{maxHangs: tt.hangCount}},
					requestTimeout: defaultRequestTimeout,
					attemptCount:   3,
				}

				done := make(chan error, 1)
				go func() {
					done <- c.sync(context.Background(), syncCtx)
				}()

				for range tt.hangCount {
					synctest.Wait()
					time.Sleep(c.requestTimeout + time.Millisecond)
				}
				synctest.Wait()

				err := <-done
				if (err != nil) != tt.wantErr {
					t.Errorf("sync() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		})
	}
}

// hangingTransport simulates a slow endpoint: the first maxHangs requests block
// until their context is canceled; subsequent requests succeed immediately with 200 OK.
type hangingTransport struct {
	count    atomic.Int32
	maxHangs int32
}

func (h *hangingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.count.Add(1) <= h.maxHangs {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}
