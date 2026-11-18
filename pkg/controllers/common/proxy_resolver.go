package common

import (
	"fmt"
	"net/http"

	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/proxyconfig"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

// ProxyResolver resolves the effective proxy configuration and builds
// pre-configured HTTP transports for outbound requests.
type ProxyResolver = proxyconfig.ProxyResolver

// WithCAFromConfigMap loads a CA bundle from a ConfigMap in the openshift-config
// namespace and appends it to the transport's trust pool. It is a no-op for an empty name.
func WithCAFromConfigMap(cmLister corelistersv1.ConfigMapLister, name, key string) httptransport.Option {
	return func(cfg *httptransport.Config) error {
		if len(name) == 0 {
			return nil
		}
		data, err := transport.LoadCAData(cmLister, name, key)
		if err != nil {
			return err
		}
		return httptransport.WithCAData(fmt.Sprintf("configmap %q", name), data)(cfg)
	}
}

type ObservableProxyResolver interface {
	ProxyResolver
	Informer() cache.SharedIndexInformer
}

// AuthProxyResolver implements ProxyResolver by reading the component proxy
// from the Authentication operator CR (when the feature gate is enabled) and
// falling back to process-level environment variables.
type AuthProxyResolver struct {
	authProxyEnabled     func() (bool, error)
	operatorAuthInformer cache.SharedIndexInformer
	operatorAuthLister   operatorv1listers.AuthenticationLister
	configMapLister      corelistersv1.ConfigMapLister
}

func NewAuthProxyResolver(
	authProxyEnabled func() (bool, error),
	operatorAuth operatorv1informers.AuthenticationInformer,
	configMapLister corelistersv1.ConfigMapLister,
) AuthProxyResolver {
	return AuthProxyResolver{
		authProxyEnabled:     authProxyEnabled,
		operatorAuthInformer: operatorAuth.Informer(),
		operatorAuthLister:   operatorAuth.Lister(),
		configMapLister:      configMapLister,
	}
}

func (r *AuthProxyResolver) Informer() cache.SharedIndexInformer { return r.operatorAuthInformer }

func (r *AuthProxyResolver) ResolveProxy() (ResolvedProxy, error) {
	return ResolveProxy(r.authProxyEnabled, r.operatorAuthLister)
}

func (r *AuthProxyResolver) NewTransport(opts ...httptransport.Option) (http.RoundTripper, error) {
	proxy, err := r.ResolveProxy()
	if err != nil {
		return nil, err
	}
	return proxyconfig.NewTransport(r.configMapLister, "openshift-config", proxy, opts...)
}
