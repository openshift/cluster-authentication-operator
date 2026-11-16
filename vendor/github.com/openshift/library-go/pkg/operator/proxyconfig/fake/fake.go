// Package fake provides test helpers for the proxyconfig package.
package fake

import (
	"net/http"

	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/proxyconfig"
)

// ProxyResolver is a test helper implementing proxyconfig.ProxyResolver.
type ProxyResolver struct {
	Proxy     proxyconfig.ResolvedProxy
	Transport http.RoundTripper
	Err       error
}

var _ proxyconfig.ProxyResolver = &ProxyResolver{}

func (f *ProxyResolver) ResolveProxy() (proxyconfig.ResolvedProxy, error) {
	return f.Proxy, f.Err
}

func (f *ProxyResolver) NewTransport(opts ...httptransport.Option) (http.RoundTripper, error) {
	return f.Transport, f.Err
}
