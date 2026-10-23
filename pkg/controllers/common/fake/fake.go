package fake

import (
	"net/http"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
)

// ProxyResolver is a test helper implementing common.ProxyResolver.
type ProxyResolver struct {
	Proxy     *common.ResolvedProxy
	Transport *http.Transport
	Err       error
}

func (f *ProxyResolver) ResolveProxy() (*common.ResolvedProxy, error) {
	return f.Proxy, f.Err
}

func (f *ProxyResolver) NewTransport(opts ...common.TransportOption) (*http.Transport, error) {
	return f.Transport, f.Err
}
