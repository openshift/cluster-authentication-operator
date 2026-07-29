package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	knet "k8s.io/apimachinery/pkg/util/net"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	ktransport "k8s.io/client-go/transport"
)

// TODO move all this to library-go

// AppendPEMCerts decodes each PEM CERTIFICATE block in data and appends it to
// pool. Unlike CertPool.AppendCertsFromPEM, it returns an error if any
// CERTIFICATE block fails to parse rather than silently skipping it. The bool
// return mirrors CertPool.AppendCertsFromPEM: true if at least one certificate
// was appended.
func AppendPEMCerts(pool *x509.CertPool, data []byte) (bool, error) {
	added := false
	index := 0
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return added, fmt.Errorf("failed to parse certificate at index %d: %w", index, err)
		}
		pool.AddCert(cert)
		added = true
		index++
	}
	return added, nil
}

// ProxyFunc returns the proxy URL for a given request URL.
type ProxyFunc func(reqURL *url.URL) (*url.URL, error)

// TransportFor returns an http.Transport for the given CA and client cert data (which may be empty).
func TransportFor(serverName string, caData, certData, keyData []byte) (http.RoundTripper, error) {
	if len(caData) == 0 && len(certData) == 0 && len(keyData) == 0 {
		return ktransport.DebugWrappers(http.DefaultTransport), nil
	}
	transport, err := NewTransport(serverName, caData, certData, keyData)
	if err != nil {
		return nil, err
	}
	return ktransport.DebugWrappers(transport), nil
}

// LoadCAData reads CA bundle bytes from a ConfigMap in openshift-config.
// It checks Data first and falls back to BinaryData for the given key.
func LoadCAData(cmLister corelistersv1.ConfigMapLister, caConfigMapName, key string) ([]byte, error) {
	cm, err := cmLister.ConfigMaps("openshift-config").Get(caConfigMapName)
	if err != nil {
		return nil, fmt.Errorf("unable to get configmap \"%s/%s\": %w", "openshift-config", caConfigMapName, err)
	}

	caData := []byte(cm.Data[key])
	if len(caData) == 0 {
		caData = cm.BinaryData[key]
	}
	if len(caData) == 0 {
		return nil, fmt.Errorf("configmap \"%s/%s\" has no CA data at key %q", "openshift-config", caConfigMapName, key)
	}
	return caData, nil
}

// NewTransport creates a fresh *http.Transport with TLS configured from the given parameters.
func NewTransport(serverName string, caData, certData, keyData []byte) (*http.Transport, error) {
	if (len(certData) == 0) != (len(keyData) == 0) {
		return nil, errors.New("cert and key data must be specified together")
	}

	// copy default transport
	transport := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: serverName,
		},
	})

	if len(caData) != 0 {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading system cert pool: %w", err)
		}

		if ok := roots.AppendCertsFromPEM(caData); !ok {
			// avoid logging data that could contain keys
			return nil, errors.New("error loading cert pool from CA data")
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
