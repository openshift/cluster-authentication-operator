package oauth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/net/http/httpproxy"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common/fake"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
)

func TestObserveComponentProxyTrustedCA(t *testing.T) {
	expectedConfig := map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"proxyTrustedCA": "/var/config/system/configmaps/v4-0-config-system-auth-proxy-ca/ca-bundle.crt",
		},
	}

	noProxy := &fake.ProxyResolver{
		Proxy: &common.ResolvedProxy{Config: &httpproxy.Config{}},
	}
	proxyWithCA := &fake.ProxyResolver{
		Proxy: &common.ResolvedProxy{
			Config:        &httpproxy.Config{HTTPSProxy: "https://proxy:3128"},
			TrustedCAName: "my-proxy-ca",
		},
	}
	proxyWithoutCA := &fake.ProxyResolver{
		Proxy: &common.ResolvedProxy{
			Config: &httpproxy.Config{HTTPSProxy: "https://proxy:3128"},
		},
	}

	tests := []struct {
		name                string
		proxyResolver       common.ProxyResolver
		existingConfig      map[string]interface{}
		expected            map[string]interface{}
		expectErrorContains string
		expectEvent         bool
	}{
		{
			name:          "no proxy returns empty config",
			proxyResolver: noProxy,
			expected:      map[string]interface{}{},
		},
		{
			name:          "proxy configured without trustedCA returns empty config",
			proxyResolver: proxyWithoutCA,
			expected:      map[string]interface{}{},
		},
		{
			name:          "proxy configured with trustedCA sets path",
			proxyResolver: proxyWithCA,
			expected:      expectedConfig,
			expectEvent:   true,
		},
		{
			name:           "trustedCA removed clears path",
			proxyResolver:  proxyWithoutCA,
			existingConfig: expectedConfig,
			expected:       map[string]interface{}{},
			expectEvent:    true,
		},
		{
			name:           "no change emits no event",
			proxyResolver:  proxyWithCA,
			existingConfig: expectedConfig,
			expected:       expectedConfig,
		},
		{
			name:                "proxy resolver error propagates error and returns existing config",
			proxyResolver:       &fake.ProxyResolver{Err: fmt.Errorf("not yet observed")},
			existingConfig:      expectedConfig,
			expected:            expectedConfig,
			expectErrorContains: "not yet observed",
		},
		{
			name:          "malformed existingConfig with non-map oauthConfig returns error",
			proxyResolver: noProxy,
			existingConfig: map[string]interface{}{
				"oauthConfig": "not-a-map",
			},
			expected:            map[string]interface{}{"oauthConfig": "not-a-map"},
			expectErrorContains: "accessor error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := tt.existingConfig
			if existing == nil {
				existing = map[string]interface{}{}
			}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			observed, errs := oauth.NewObserveComponentProxyTrustedCA(tt.proxyResolver)(nil, recorder, existing)

			if tt.expectErrorContains != "" {
				require.NotEmpty(t, errs)
				require.ErrorContains(t, errs[0], tt.expectErrorContains)
			} else {
				require.Empty(t, errs)
			}

			observedValue, _, _ := unstructured.NestedString(observed, "oauthConfig", "proxyTrustedCA")
			expectedValue, _, _ := unstructured.NestedString(tt.expected, "oauthConfig", "proxyTrustedCA")
			require.Equal(t, expectedValue, observedValue)

			recordedEvents := recorder.Events()
			if tt.expectEvent {
				require.Len(t, recordedEvents, 1)
				require.Equal(t, "ObserveComponentProxyTrustedCA", recordedEvents[0].Reason)
			} else {
				require.Empty(t, recordedEvents)
			}
		})
	}
}
