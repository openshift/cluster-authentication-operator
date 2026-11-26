// Package fakeproxy provides test helpers for the common proxy resolver.
package fakeproxy

import (
	"net/http"

	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/proxyconfig"
)

// ProxyResolver is a test helper implementing common.ProxyResolver.
// NewTransport ignores the options and always returns Transport, so the same
// transport is used with and without the proxy.
type ProxyResolver struct {
	Proxy     proxyconfig.ResolvedProxy
	Transport http.RoundTripper
	Err       error
}

func (f *ProxyResolver) ResolveProxy() (proxyconfig.ResolvedProxy, error) {
	return f.Proxy, f.Err
}

func (f *ProxyResolver) NewTransport(opts ...httptransport.Option) (http.RoundTripper, error) {
	return f.Transport, f.Err
}
