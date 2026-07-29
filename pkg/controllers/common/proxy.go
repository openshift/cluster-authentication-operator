package common

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

// ResolvedProxy holds the effective proxy configuration for authentication components.
type ResolvedProxy struct {
	*httpproxy.Config
	TrustedCAName string
}

func (p *ResolvedProxy) IsProxyConfigured() bool {
	return len(p.HTTPProxy) != 0 || len(p.HTTPSProxy) != 0
}

// ProxyFunc returns a function that resolves the proxy URL for a given request URL.
func (p *ResolvedProxy) ProxyFunc() transport.ProxyFunc {
	return transport.ProxyFunc(p.Config.ProxyFunc())
}

// ResolveProxy reads the component-scoped proxy from the Authentication
// operator CR (when the feature gate is enabled) and returns the effective proxy
// settings. When no component proxy is configured, it falls back to the process
// environment (which reflects the cluster-wide proxy).
func ResolveProxy(
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthLister operatorv1listers.AuthenticationLister,
) (*ResolvedProxy, error) {
	authProxy, err := getComponentProxyConfig(featureGateAccessor, operatorAuthLister)
	if err != nil {
		return nil, err
	}

	if authProxy != nil {
		return &ResolvedProxy{
			TrustedCAName: authProxy.TrustedCA.Name,
			Config: &httpproxy.Config{
				HTTPProxy:  authProxy.HTTPProxy,
				HTTPSProxy: authProxy.HTTPSProxy,
				NoProxy:    mergeNoProxy(authProxy.NoProxy),
			},
		}, nil
	}

	return &ResolvedProxy{
		Config: httpproxy.FromEnvironment(),
	}, nil
}

// getComponentProxyConfig returns the component-scoped proxy configuration
// from operator.openshift.io/v1 Authentication if the feature gate is enabled.
// Returns (nil, nil) when the gate is disabled or the resource is not found.
func getComponentProxyConfig(
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthLister operatorv1listers.AuthenticationLister,
) (*operatorv1.AuthenticationProxyConfig, error) {
	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return nil, fmt.Errorf("failed to get current feature gates: %w", err)
	}
	if !featureGates.Enabled(features.FeatureGateAuthenticationComponentProxy) {
		return nil, nil
	}

	authOp, err := operatorAuthLister.Get("cluster")
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get operator.openshift.io/v1 authentication/cluster: %w", err)
	}

	proxy := authOp.Spec.Proxy
	if proxy.HTTPProxy == "" && proxy.HTTPSProxy == "" {
		return nil, nil
	}
	return &proxy, nil
}

// staticNoProxyEntries contains cluster-internal addresses that must bypass the
// proxy. Auth components connect to internal services via DNS names covered by
// .svc and .cluster.local. The kubernetes API service IP (KUBERNETES_SERVICE_HOST)
// is included explicitly because Go's in-cluster client connects to it by raw IP,
// which does not match the hostname-based entries above.
var staticNoProxyEntries = func() []string {
	entries := []string{".cluster.local", ".svc", "127.0.0.1", "localhost"}
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		entries = append(entries, host)
	}
	return entries
}()

// mergeNoProxy combines user-provided noProxy entries with static cluster-internal
// defaults. The result is deduplicated and sorted for deterministic output.
func mergeNoProxy(userNoProxy []string) string {
	entries := sets.New[string](staticNoProxyEntries...)
	entries.Insert(userNoProxy...)
	return strings.Join(sets.List(entries), ",")
}
