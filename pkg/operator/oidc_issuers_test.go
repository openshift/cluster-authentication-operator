package operator

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

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

func TestOIDCIssuerDiscoveryURLs_discoveryURLOverride(t *testing.T) {
	auth := &configv1.Authentication{Spec: configv1.AuthenticationSpec{OIDCProviders: []configv1.OIDCProvider{
		{Issuer: configv1.TokenIssuer{
			URL:          "https://issuer.example.com",
			DiscoveryURL: "https://discovery.internal.example.net/custom/openid-configuration",
		}},
		{Issuer: configv1.TokenIssuer{URL: "https://plain.example.com/"}},
	}}}

	// the proxy checks must target the discovery host, not the issuer host
	if diff := cmp.Diff([]string{
		"https://discovery.internal.example.net/custom/openid-configuration",
		"https://plain.example.com/.well-known/openid-configuration",
	}, oidcIssuerDiscoveryURLs(auth)); diff != "" {
		t.Errorf("unexpected discovery URLs (-want +got):\n%s", diff)
	}
}

func Test_objectName(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "ca"}}
	for _, obj := range []interface{}{cm, cache.DeletedFinalStateUnknown{Key: "openshift-config/ca", Obj: cm}} {
		if name, ok := objectName(obj); !ok || name != "ca" {
			t.Errorf("objectName(%T) = %q, %v, want \"ca\", true", obj, name, ok)
		}
	}
	if _, ok := objectName("not an object"); ok {
		t.Error("expected objectName to fail for a non-object")
	}
}

func Test_parseEndpointURLs(t *testing.T) {
	got := parseEndpointURLs([]string{"https://a.example.com", "://invalid", "https://b.example.com/path"})
	var gotStrings []string
	for _, u := range got {
		gotStrings = append(gotStrings, u.String())
	}
	if diff := cmp.Diff([]string{"https://a.example.com", "https://b.example.com/path"}, gotStrings); diff != "" {
		t.Errorf("unexpected URLs (-want +got):\n%s", diff)
	}
}
