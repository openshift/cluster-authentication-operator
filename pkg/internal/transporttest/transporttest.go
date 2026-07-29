package transporttest

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

// UnwrapTransport recursively unwraps a RoundTripper (e.g. from
// DebugWrappers) until it reaches the underlying *http.Transport.
func UnwrapTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	type unwrapper interface {
		WrappedRoundTripper() http.RoundTripper
	}
	for {
		if tr, ok := rt.(*http.Transport); ok {
			return tr
		}
		u, ok := rt.(unwrapper)
		if !ok {
			t.Fatalf("cannot unwrap %T to *http.Transport", rt)
		}
		rt = u.WrappedRoundTripper()
	}
}

// MakeSelfSignedCA generates a self-signed CA certificate and returns
// the CA object and its PEM-encoded certificate bytes.
func MakeSelfSignedCA(t *testing.T) (*crypto.CA, []byte) {
	t.Helper()
	tmpDir := t.TempDir()
	ca, err := crypto.MakeSelfSignedCA(
		path.Join(tmpDir, "ca.crt"),
		path.Join(tmpDir, "ca.key"),
		"", "testCA", time.Hour*24,
	)
	if err != nil {
		t.Fatalf("failed to create self-signed CA: %v", err)
	}
	certPEM, _, err := ca.Config.GetPEMBytes()
	if err != nil {
		t.Fatalf("failed to get CA PEM bytes: %v", err)
	}
	return ca, certPEM
}

// MustParseURL parses a raw URL string and fails the test if it is invalid.
func MustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}
	return u
}

// RootCAs returns the RootCAs pool from a transport's TLS config,
// failing the test if TLSClientConfig is nil.
func RootCAs(t *testing.T, tr *http.Transport) *x509.CertPool {
	t.Helper()
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	return tr.TLSClientConfig.RootCAs
}

// RequirePoolContains verifies that every given PEM certificate is
// trusted by the pool, failing the test otherwise.
func RequirePoolContains(t *testing.T, pool *x509.CertPool, pemData ...[]byte) {
	t.Helper()
	if pool == nil {
		t.Fatal("RootCAs pool is nil")
	}
	opts := x509.VerifyOptions{Roots: pool}
	for _, p := range pemData {
		cert := MustParseCert(t, p)
		if _, err := cert.Verify(opts); err != nil {
			t.Errorf("expected cert %q to be trusted: %v", cert.Subject, err)
		}
	}
}

// RequirePoolNotContains verifies that none of the given PEM
// certificates are trusted by the pool.
func RequirePoolNotContains(t *testing.T, pool *x509.CertPool, pemData ...[]byte) {
	t.Helper()
	if pool == nil {
		t.Fatal("RootCAs pool is nil")
	}
	opts := x509.VerifyOptions{Roots: pool}
	for _, p := range pemData {
		cert := MustParseCert(t, p)
		if _, err := cert.Verify(opts); err == nil {
			t.Errorf("expected cert %q to NOT be trusted", cert.Subject)
		}
	}
}

// MustParseCert decodes a PEM block and parses the first certificate.
func MustParseCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
