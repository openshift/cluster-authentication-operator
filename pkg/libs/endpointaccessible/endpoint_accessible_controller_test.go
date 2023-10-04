package endpointaccessible

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_endpointAccessibleController_sync(t *testing.T) {
	maxCheckLatency := 55 * time.Second

	systemRootCAs, err := x509.SystemCertPool()
	if err != nil {
		t.Errorf("unexpected error when getting system cert pool: %v", err)
	}

	getTLSConfigFn := func(serverName string, returnErr error) func() (*tls.Config, error) {
		return func() (*tls.Config, error) {
			return &tls.Config{
				RootCAs:    systemRootCAs,
				ServerName: serverName,
			}, returnErr
		}
	}

	getTLSConfigFnEmptyRootCAs := func(serverName string, returnErr error) func() (*tls.Config, error) {
		return func() (*tls.Config, error) {
			return &tls.Config{
				RootCAs:    x509.NewCertPool(),
				ServerName: serverName,
			}, returnErr
		}
	}

	tests := []struct {
		name              string
		endpointListFn    EndpointListFunc
		getTLSConfigFn    EndpointTLSConfigFunc
		lastCheckTime     time.Time
		lastEndpoints     sets.Set[string]
		lastServerName    string
		lastCA            *x509.CertPool
		wantCheckExecuted bool
		wantErr           bool
	}{
		{
			name:           "all endpoints working",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			wantCheckExecuted: true,
		},
		{
			name:           "all endpoints working with tls config",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			wantCheckExecuted: true,
		},
		{
			name:           "check working when endpoints change",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			lastEndpoints:     sets.New[string]("https://www.google.com"),
			lastCheckTime:     time.Now().Add(-1 * time.Second),
			lastServerName:    "google.com",
			lastCA:            systemRootCAs,
			wantCheckExecuted: true,
		},
		{
			name:           "check working when check is due",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			lastEndpoints:     sets.New[string]("https://google.com"),
			lastCheckTime:     time.Now().Add(-2 * maxCheckLatency),
			lastServerName:    "google.com",
			lastCA:            systemRootCAs,
			wantCheckExecuted: true,
		},
		{
			name:           "check working when tls server name changes",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			lastEndpoints:     sets.New[string]("https://google.com"),
			lastCheckTime:     time.Now().Add(-1 * time.Second),
			lastServerName:    "redhat.com",
			lastCA:            systemRootCAs,
			wantCheckExecuted: true,
		},
		{
			name:           "check working when tls root CAs change",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			lastEndpoints:     sets.New[string]("https://google.com"),
			lastCheckTime:     time.Now().Add(-1 * time.Second),
			lastServerName:    "google.com",
			lastCA:            x509.NewCertPool(),
			wantCheckExecuted: true,
		},
		{
			name:           "check skipped when no changes in parameters and check is not due",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			lastEndpoints:     sets.New[string]("https://google.com"),
			lastCheckTime:     time.Now().Add(-1 * time.Second),
			lastServerName:    "google.com",
			lastCA:            systemRootCAs,
			wantCheckExecuted: false,
			wantErr:           false,
		},
		{
			name:           "check fails when tls config fails",
			getTLSConfigFn: getTLSConfigFn("google.com", fmt.Errorf("tls config error")),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			wantCheckExecuted: false,
			wantErr:           true,
		},
		{
			name:           "check fails when tls server name invalid",
			getTLSConfigFn: getTLSConfigFn("g00gle.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			wantCheckExecuted: true,
			wantErr:           true,
		},
		{
			name:           "check fails when tls rootCAs invalid",
			getTLSConfigFn: getTLSConfigFnEmptyRootCAs("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com"}, nil
			},
			wantCheckExecuted: true,
			wantErr:           true,
		},
		{
			name: "endpoints lister error",
			endpointListFn: func() ([]string, error) {
				return nil, fmt.Errorf("some error")
			},
			wantCheckExecuted: false,
			wantErr:           true,
		},
		{
			name:           "non working endpoints",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"https://google.com", "https://nonexistenturl.com"}, nil
			},
			wantCheckExecuted: true,
			wantErr:           true,
		},
		{
			name:           "invalid url",
			getTLSConfigFn: getTLSConfigFn("google.com", nil),
			endpointListFn: func() ([]string, error) {
				return []string{"htt//bad`string"}, nil
			},
			wantCheckExecuted: true,
			wantErr:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &endpointAccessibleController{
				operatorClient:  v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil),
				getTLSConfigFn:  tt.getTLSConfigFn,
				endpointListFn:  tt.endpointListFn,
				maxCheckLatency: maxCheckLatency,
				lastEndpoints:   tt.lastEndpoints,
				lastCheckTime:   tt.lastCheckTime,
				lastServerName:  tt.lastServerName,
				lastCA:          tt.lastCA,
			}
			prevLastCheckTime := c.lastCheckTime
			if err := c.sync(context.Background(), factory.NewSyncContext(tt.name, events.NewInMemoryRecorder(tt.name))); (err != nil) != tt.wantErr {
				t.Errorf("sync() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantCheckExecuted != (!prevLastCheckTime.Equal(c.lastCheckTime)) {
				t.Errorf("sync() check was executed when it should have been skipped")
			}
		})
	}
}
