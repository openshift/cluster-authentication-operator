package common

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"

	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
	"github.com/openshift/library-go/pkg/network/httptransport"
)

type transportConfig struct {
	opts []httptransport.Option
}

// TransportOption configures the trust pool for NewTransport.
type TransportOption func(cfg *transportConfig, cmLister corelistersv1.ConfigMapLister) error

func WithCertPool(pool *x509.CertPool) TransportOption {
	return func(cfg *transportConfig, _ corelistersv1.ConfigMapLister) error {
		cfg.opts = append(cfg.opts, httptransport.WithCertPool(pool))
		return nil
	}
}

func WithCA(name string, data []byte) TransportOption {
	return func(cfg *transportConfig, _ corelistersv1.ConfigMapLister) error {
		cfg.opts = append(cfg.opts, httptransport.WithCAData(name, data))
		return nil
	}
}

func WithCAFromConfigMap(name, key string) TransportOption {
	return func(cfg *transportConfig, cmLister corelistersv1.ConfigMapLister) error {
		if len(name) == 0 {
			return nil
		}
		data, err := transport.LoadCAData(cmLister, name, key)
		if err != nil {
			return err
		}
		cfg.opts = append(cfg.opts, httptransport.WithCAData(fmt.Sprintf("configmap %q", name), data))
		return nil
	}
}

// WithoutProxy disables proxy use for the constructed round tripper.
func WithoutProxy() TransportOption {
	return func(cfg *transportConfig, _ corelistersv1.ConfigMapLister) error {
		cfg.opts = append(cfg.opts, httptransport.WithProxyFunc(nil))
		return nil
	}
}

type ProxyResolver interface {
	ResolveProxy() (*ResolvedProxy, error)
	NewTransport(opts ...TransportOption) (http.RoundTripper, error)
}

type ObservableProxyResolver interface {
	ProxyResolver
	Informer() cache.SharedIndexInformer
}

type AuthProxyResolver struct {
	authProxyEnabled     func() (bool, error)
	operatorAuthInformer cache.SharedIndexInformer
	operatorAuthLister   operatorv1listers.AuthenticationLister
	configMapLister      corelistersv1.ConfigMapLister
}

func NewAuthProxyResolver(authProxyEnabled func() (bool, error), operatorAuth operatorv1informers.AuthenticationInformer, configMapLister corelistersv1.ConfigMapLister) AuthProxyResolver {
	return AuthProxyResolver{authProxyEnabled: authProxyEnabled, operatorAuthInformer: operatorAuth.Informer(), operatorAuthLister: operatorAuth.Lister(), configMapLister: configMapLister}
}

func (r *AuthProxyResolver) Informer() cache.SharedIndexInformer { return r.operatorAuthInformer }

func (r *AuthProxyResolver) ResolveProxy() (*ResolvedProxy, error) {
	return ResolveProxy(r.authProxyEnabled, r.operatorAuthLister)
}

func (r *AuthProxyResolver) NewTransport(opts ...TransportOption) (http.RoundTripper, error) {
	proxy, err := r.ResolveProxy()
	if err != nil {
		return nil, err
	}
	return NewTransport(r.configMapLister, proxy, opts...)
}

func NewTransport(configMapLister corelistersv1.ConfigMapLister, proxy *ResolvedProxy, opts ...TransportOption) (http.RoundTripper, error) {
	var cfg transportConfig
	for _, opt := range opts {
		if err := opt(&cfg, configMapLister); err != nil {
			return nil, err
		}
	}
	if len(proxy.TrustedCAName) > 0 {
		proxyCA, err := transport.LoadCAData(configMapLister, proxy.TrustedCAName, "ca-bundle.crt")
		if err != nil {
			return nil, err
		}
		cfg.opts = append(cfg.opts, httptransport.WithCAData(fmt.Sprintf("proxy trustedCA %q", proxy.TrustedCAName), proxyCA))
	}
	if proxy.IsProxyConfigured() {
		proxyFunc := (&httpproxy.Config{HTTPProxy: proxy.HTTPProxy, HTTPSProxy: proxy.HTTPSProxy, NoProxy: proxy.NoProxy}).ProxyFunc()
		cfg.opts = append(cfg.opts, httptransport.WithProxyFunc(func(req *http.Request) (*url.URL, error) { return proxyFunc(req.URL) }))
	}
	return httptransport.NewRoundTripper(cfg.opts...)
}
