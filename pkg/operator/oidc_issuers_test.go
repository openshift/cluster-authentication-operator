package operator

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
)

func TestOIDCIssuers(t *testing.T) {
	provider := func(url, ca string) configv1.OIDCProvider {
		return configv1.OIDCProvider{Issuer: configv1.TokenIssuer{
			URL:                  url,
			CertificateAuthority: configv1.ConfigMapNameReference{Name: ca},
		}}
	}
	auth := &configv1.Authentication{Spec: configv1.AuthenticationSpec{OIDCProviders: []configv1.OIDCProvider{
		provider("https://a.example.com/", "ca-a"),
		provider("https://b.example.com", ""),
		provider("", "ca-empty-url"),
		provider("https://c.example.com", "ca-a"),
	}}}

	if diff := cmp.Diff([]string{
		"https://a.example.com/.well-known/openid-configuration",
		"https://b.example.com/.well-known/openid-configuration",
		"https://c.example.com/.well-known/openid-configuration",
	}, oidcIssuerDiscoveryURLs(auth)); diff != "" {
		t.Errorf("unexpected discovery URLs (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{"ca-a", "ca-empty-url"}, oidcIssuerCAConfigMapNames(auth)); diff != "" {
		t.Errorf("unexpected CA names (-want +got):\n%s", diff)
	}

	if got := oidcIssuerDiscoveryURLs(&configv1.Authentication{}); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
