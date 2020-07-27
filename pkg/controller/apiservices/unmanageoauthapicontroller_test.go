package apiservices

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorv1 "github.com/openshift/api/operator/v1"
	fakeoperator "github.com/openshift/client-go/operator/clientset/versioned/fake"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_syncUnmanageAPIServicesController(t *testing.T) {
	tests := []struct {
		name           string
		operatorStatus *operatorv1.AuthenticationStatus
		changed        bool
		expectErr      bool
	}{
		{
			name:      "operator not found",
			expectErr: true,
		},
		{
			name: "managed set to true",
			operatorStatus: &operatorv1.AuthenticationStatus{
				ManagingOAuthAPIServer: true,
			},
			changed: true,
		},
		{
			name: "managed set to false = no action",
			operatorStatus: &operatorv1.AuthenticationStatus{
				ManagingOAuthAPIServer: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authOps := []runtime.Object{}
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.operatorStatus != nil {
				operatorObj := &operatorv1.Authentication{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Status: *tt.operatorStatus,
				}

				if err := indexer.Add(operatorObj); err != nil {
					t.Fatal(err)
				}
				authOps = append(authOps, operatorObj)
			}
			fakeOperatorClient := fakeoperator.NewSimpleClientset(authOps...)
			operatorLister := operatorv1listers.NewAuthenticationLister(indexer)

			testRecorder := events.NewInMemoryRecorder("test")
			if gotErr := syncUnmanageAPIServicesController("testUnmanagedController", fakeOperatorClient.OperatorV1(), operatorLister)(context.TODO(), testSyncContext{recorder: testRecorder}); tt.expectErr != (gotErr != nil) {
				t.Errorf("syncUnmanageAPIServicesController() => expected error: %v, but got %v", tt.expectErr, gotErr)
			}

			var updateObserved bool
			for _, a := range fakeOperatorClient.Actions() {
				if a.GetVerb() == "update" {
					updateObserved = true
					break
				}
			}
			if !tt.changed {
				if len(testRecorder.Events()) > 0 || updateObserved {
					t.Errorf("expected the operator status to be the same, but that did not happen; update observed: %v; events: %v", updateObserved, testRecorder.Events())
				}
			} else if len(testRecorder.Events()) == 0 || !updateObserved {
				t.Errorf("expected change of the operator status:, but that did not happen; update observed: %v; events: %v", updateObserved, testRecorder.Events())
			}
		})
	}
}

type testSyncContext struct {
	recorder events.Recorder
}

func (c testSyncContext) Recorder() events.Recorder { return c.recorder }

func (c testSyncContext) Queue() workqueue.RateLimitingInterface { return nil }

func (c testSyncContext) QueueKey() string { return "testkey" }
