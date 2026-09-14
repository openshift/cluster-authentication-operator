package deploymentutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestProxyEnvVars(t *testing.T) {
	tests := []struct {
		name                           string
		httpProxy, httpsProxy, noProxy string
		want                           []corev1.EnvVar
	}{
		{
			name:       "all proxy values",
			httpProxy:  "http://proxy.example.com:8080",
			httpsProxy: "https://proxy.example.com:8443",
			noProxy:    ".svc,localhost",
			want: []corev1.EnvVar{
				{Name: "NO_PROXY", Value: ".svc,localhost"},
				{Name: "HTTP_PROXY", Value: "http://proxy.example.com:8080"},
				{Name: "HTTPS_PROXY", Value: "https://proxy.example.com:8443"},
			},
		},
		{name: "empty proxy values"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ProxyEnvVars(tt.httpProxy, tt.httpsProxy, tt.noProxy))
		})
	}
}
