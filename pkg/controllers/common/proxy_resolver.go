package common

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"

	knet "k8s.io/apimachinery/pkg/util/net"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

// transportConfig holds the cert pool being assembled by TransportOptions.
type transportConfig struct {
	pool *x509.CertPool
}

func (c *transportConfig) appendToPool(data []byte) error {
	if c.pool == nil {
		c.pool = x509.NewCertPool()
	}
	ok, err := transport.AppendPEMCerts(c.pool, data)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("no certificates found in PEM data")
	}
	return nil
}

// TransportOption configures the trust pool for NewTransport.
type TransportOption func(cfg *transportConfig, cmLister corelistersv1.ConfigMapLister) error

// WithCertPool provides a pre-built certificate pool as the base trust
// pool. The proxy's trusted CA (if any) is appended to this pool.
// This avoids re-parsing CA bundles when multiple transports share the
// same trust anchors.
func WithCertPool(pool *x509.CertPool) TransportOption {
	return func(cfg *transportConfig, _ corelistersv1.ConfigMapLister) error {
		cfg.pool = pool
		return nil
	}
}

// WithCA appends raw CA certificate bytes to the transport's trust pool.
// The name identifies the source for error messages.
func WithCA(name string, data []byte) TransportOption {
	return func(cfg *transportConfig, _ corelistersv1.ConfigMapLister) error {
		if len(data) == 0 {
			return nil
		}
		if err := cfg.appendToPool(data); err != nil {
			return fmt.Errorf("failed to append CA certificates to cert pool for source %q: %w", name, err)
		}
		return nil
	}
}

// WithCAFromConfigMap loads a CA bundle from a ConfigMap in the openshift-config
// namespace and appends it to the transport's trust pool.
func WithCAFromConfigMap(name, key string) TransportOption {
	return func(cfg *transportConfig, cmLister corelistersv1.ConfigMapLister) error {
		if len(name) == 0 {
			return nil
		}
		data, err := transport.LoadCAData(cmLister, name, key)
		if err != nil {
			return err
		}
		if err := cfg.appendToPool(data); err != nil {
			return fmt.Errorf("failed to append CA certificates to cert pool for configmap %q: %w", name, err)
		}
		return nil
	}
}

// ProxyResolver resolves the effective proxy configuration and builds
// pre-configured HTTP transports for outbound requests.
type ProxyResolver interface {
	ResolveProxy() (*ResolvedProxy, error)

	// NewTransport returns an *http.Transport with proxy settings, the
	// proxy's trusted CA, and any additional CA sources merged into the
	// trust pool. The transport is initialized with knet.SetTransportDefaults.
	NewTransport(opts ...TransportOption) (*http.Transport, error)
}

// AuthProxyResolver implements ProxyResolver by reading the component proxy
// from the Authentication operator CR (when the feature gate is enabled) and
// falling back to process-level environment variables.
type AuthProxyResolver struct {
	operatorAuthInformer cache.SharedIndexInformer
	operatorAuthLister   operatorv1listers.AuthenticationLister
	configMapLister      corelistersv1.ConfigMapLister
	featureGateAccessor  featuregates.FeatureGateAccess
}

func NewAuthProxyResolver(
	operatorAuth operatorv1informers.AuthenticationInformer,
	configMapLister corelistersv1.ConfigMapLister,
	featureGateAccessor featuregates.FeatureGateAccess,
) AuthProxyResolver {
	return AuthProxyResolver{
		operatorAuthInformer: operatorAuth.Informer(),
		operatorAuthLister:   operatorAuth.Lister(),
		configMapLister:      configMapLister,
		featureGateAccessor:  featureGateAccessor,
	}
}

func (r *AuthProxyResolver) Informer() cache.SharedIndexInformer {
	return r.operatorAuthInformer
}

func (r *AuthProxyResolver) ResolveProxy() (*ResolvedProxy, error) {
	return ResolveProxy(r.featureGateAccessor, r.operatorAuthLister)
}

func (r *AuthProxyResolver) NewTransport(opts ...TransportOption) (*http.Transport, error) {
	proxy, err := r.ResolveProxy()
	if err != nil {
		return nil, err
	}

	var cfg transportConfig
	for _, opt := range opts {
		if err := opt(&cfg, r.configMapLister); err != nil {
			return nil, err
		}
	}

	if len(proxy.TrustedCAName) > 0 {
		proxyCA, err := transport.LoadCAData(r.configMapLister, proxy.TrustedCAName, "ca-bundle.crt")
		if err != nil {
			return nil, err
		}
		if err := cfg.appendToPool(proxyCA); err != nil {
			return nil, fmt.Errorf("failed to append CA certificates to cert pool for proxy trustedCA %q: %w", proxy.TrustedCAName, err)
		}
	}

	tr := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: cfg.pool,
		},
	})

	if proxy.IsProxyConfigured() {
		proxyCfg := httpproxy.Config{
			HTTPProxy:  proxy.HTTPProxy,
			HTTPSProxy: proxy.HTTPSProxy,
			NoProxy:    proxy.NoProxy,
		}
		proxyFunc := proxyCfg.ProxyFunc()
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxyFunc(req.URL)
		}
	}

	return tr, nil
}
