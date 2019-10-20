package operator2

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"k8s.io/apimachinery/pkg/util/net"
	ktransport "k8s.io/client-go/transport"
)

// TODO move all this to library-go

var mockRoundTripResponses = map[string]*http.Response{}

type mockRoundTripper struct{}

func (m *mockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	uri := request.URL.String()
	if response, ok := mockRoundTripResponses[uri]; ok {
		return response, nil
	}

	return nil, fmt.Errorf("no mock response for %s", uri)
}

// transportFor returns an http.Transport for the given ca and client cert data (which may be empty)
func transportFor(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	if len(mockRoundTripResponses) > 0 {
		return &mockRoundTripper{}, nil
	}

	transport, err := transportForInner(serverName, caData, certData, keyData)
	if err != nil {
		return nil, err
	}
	return ktransport.DebugWrappers(transport), nil
}

func transportForInner(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	if len(caData) == 0 && len(certData) == 0 && len(keyData) == 0 {
		return http.DefaultTransport, nil
	}

	if (len(certData) == 0) != (len(keyData) == 0) {
		return nil, errors.New("cert and key data must be specified together")
	}

	// copy default transport
	transport := net.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: serverName,
		},
	})

	if len(caData) != 0 {
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(caData); !ok {
			// avoid logging data that could contain keys
			return nil, errors.New("error loading cert pool from ca data")
		}
		transport.TLSClientConfig.RootCAs = roots
	}

	if len(certData) != 0 {
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			// avoid logging data that will contain keys
			return nil, errors.New("error loading x509 keypair from cert and key data")
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return transport, nil
}
