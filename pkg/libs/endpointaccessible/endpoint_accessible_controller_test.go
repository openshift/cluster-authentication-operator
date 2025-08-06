package endpointaccessible

import (
	"context"
	"fmt"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_endpointAccessibleController_sync(t *testing.T) {
	tests := []struct {
		name                      string
		endpointListFn            EndpointListFunc
		endpointCheckDisabledFunc EndpointCheckDisabledFunc
		wantErr                   bool
	}{
		{
			name: "all endpoints working",
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
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
				return []string{"https://httpbin.org/status/500"}, nil
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
			c := &endpointAccessibleController{
				operatorClient:            v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
				endpointListFn:            tt.endpointListFn,
				endpointCheckDisabledFunc: tt.endpointCheckDisabledFunc,
			}
			if err := c.sync(context.Background(), factory.NewSyncContext(tt.name, events.NewInMemoryRecorder(tt.name, clocktesting.NewFakePassiveClock(time.Now())))); (err != nil) != tt.wantErr {
				t.Errorf("sync() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
