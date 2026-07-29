package common

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"github.com/openshift/cluster-authentication-operator/pkg/internal/transporttest"
)

var (
	enabledGate = featuregates.NewHardcodedFeatureGateAccess(
		[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
		nil,
	)
	disabledGate = featuregates.NewHardcodedFeatureGateAccess(
		nil,
		[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
	)
)

func TestResolveProxy(t *testing.T) {
	errorGate := featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, make(chan struct{}), errors.New("not yet observed"))

	proxySet := &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: operatorv1.AuthenticationSpec{
			Proxy: operatorv1.AuthenticationProxyConfig{
				HTTPSProxy: "http://proxy:3128",
				TrustedCA:  operatorv1.AuthenticationConfigMapReference{Name: "my-ca-bundle"},
			},
		},
	}
	proxyEmpty := &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}

	proxyConfig := func(http, https, noProxy string) *httpproxy.Config {
		return &httpproxy.Config{HTTPProxy: http, HTTPSProxy: https, NoProxy: noProxy}
	}

	tests := []struct {
		name       string
		gate       featuregates.FeatureGateAccess
		lister     operatorv1listers.AuthenticationLister
		envHTTP    string
		envHTTPS   string
		envNoProxy string
		want       *ResolvedProxy
		wantErr    string
	}{
		{
			name:    "gate disabled falls back to env",
			gate:    disabledGate,
			lister:  newOperatorAuthLister(proxySet),
			envHTTP: "http://cluster:3128",
			want:    &ResolvedProxy{Config: proxyConfig("http://cluster:3128", "", "")},
		},
		{
			name:    "gate error propagates",
			gate:    errorGate,
			lister:  newOperatorAuthLister(proxySet),
			wantErr: "failed to get current feature gates: not yet observed",
		},
		{
			name:    "lister error propagates",
			gate:    enabledGate,
			lister:  newErrorAuthLister(errors.New("connection refused")),
			wantErr: "failed to get operator.openshift.io/v1 authentication/cluster: connection refused",
		},
		{
			name:     "CR not found falls back to env",
			gate:     enabledGate,
			lister:   newOperatorAuthLister(nil),
			envHTTPS: "http://cluster:3129",
			want:     &ResolvedProxy{Config: proxyConfig("", "http://cluster:3129", "")},
		},
		{
			name:   "CR exists but proxy is zero-value falls back to env",
			gate:   enabledGate,
			lister: newOperatorAuthLister(proxyEmpty),
			want:   &ResolvedProxy{Config: proxyConfig("", "", "")},
		},
		{
			name:    "component proxy set returns active proxy with trustedCA",
			gate:    enabledGate,
			lister:  newOperatorAuthLister(proxySet),
			envHTTP: "http://should-be-ignored:3128",
			want: &ResolvedProxy{

				TrustedCAName: "my-ca-bundle",
				Config:        proxyConfig("", "http://proxy:3128", expectedNoProxy()),
			},
		},
		{
			name: "component proxy with user noProxy merges with defaults",
			gate: enabledGate,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://component:3128",
						NoProxy:   []string{"idp.example.com", ".corp.example.com"},
					},
				},
			}),
			want: &ResolvedProxy{

				Config: proxyConfig("http://component:3128", "", expectedNoProxy("idp.example.com", ".corp.example.com")),
			},
		},
		{
			name: "component proxy with user noProxy duplicating defaults deduplicates",
			gate: enabledGate,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://component:3128",
						NoProxy:   []string{".svc", "idp.example.com", "127.0.0.1"},
					},
				},
			}),
			want: &ResolvedProxy{

				Config: proxyConfig("http://component:3128", "", expectedNoProxy("idp.example.com")),
			},
		},
		{
			name: "component proxy with only httpsProxy overrides env",
			gate: enabledGate,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://component:3129",
					},
				},
			}),
			envHTTP:  "http://cluster:3128",
			envHTTPS: "http://cluster:3129",
			want: &ResolvedProxy{

				Config: proxyConfig("", "http://component:3129", expectedNoProxy()),
			},
		},
		{
			name:   "neither configured returns empty",
			gate:   disabledGate,
			lister: newOperatorAuthLister(nil),
			want:   &ResolvedProxy{Config: proxyConfig("", "", "")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", tt.envHTTP)
			t.Setenv("HTTPS_PROXY", tt.envHTTPS)
			t.Setenv("NO_PROXY", tt.envNoProxy)

			got, err := ResolveProxy(tt.gate, tt.lister)

			var errMsg string
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != tt.wantErr {
				t.Fatalf("error = %q, want %q", errMsg, tt.wantErr)
			}
			if tt.wantErr != "" {
				return
			}

			if got.HTTPProxy != tt.want.HTTPProxy {
				t.Errorf("HTTPProxy = %q, want %q", got.HTTPProxy, tt.want.HTTPProxy)
			}
			if got.HTTPSProxy != tt.want.HTTPSProxy {
				t.Errorf("HTTPSProxy = %q, want %q", got.HTTPSProxy, tt.want.HTTPSProxy)
			}
			if got.NoProxy != tt.want.NoProxy {
				t.Errorf("NoProxy = %q, want %q", got.NoProxy, tt.want.NoProxy)
			}
			if got.TrustedCAName != tt.want.TrustedCAName {
				t.Errorf("TrustedCAName = %q, want %q", got.TrustedCAName, tt.want.TrustedCAName)
			}
		})
	}
}

func TestResolvedProxy_IsProxyConfigured(t *testing.T) {
	tests := []struct {
		name  string
		proxy *ResolvedProxy
		want  bool
	}{
		{
			name:  "both empty",
			proxy: &ResolvedProxy{Config: &httpproxy.Config{}},
			want:  false,
		},
		{
			name:  "http proxy set",
			proxy: &ResolvedProxy{Config: &httpproxy.Config{HTTPProxy: "http://proxy:3128"}},
			want:  true,
		},
		{
			name:  "https proxy set",
			proxy: &ResolvedProxy{Config: &httpproxy.Config{HTTPSProxy: "http://proxy:3128"}},
			want:  true,
		},
		{
			name:  "both set",
			proxy: &ResolvedProxy{Config: &httpproxy.Config{HTTPProxy: "http://proxy:3128", HTTPSProxy: "http://proxy:3129"}},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.proxy.IsProxyConfigured(); got != tt.want {
				t.Errorf("IsProxyConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolvedProxy_ProxyFunc(t *testing.T) {
	httpsURL := transporttest.MustParseURL(t, "https://idp.example.com/.well-known/openid-configuration")
	httpURL := transporttest.MustParseURL(t, "http://idp.example.com/callback")

	tests := []struct {
		name         string
		featureGate  featuregates.FeatureGateAccess
		authLister   operatorv1listers.AuthenticationLister
		reqURL       *url.URL
		wantProxyURL string
	}{
		{
			name:        "feature gate disabled returns nil proxy (no env)",
			featureGate: disabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://should-not-be-used:3128",
					},
				},
			}),
			reqURL: httpsURL,
		},
		{
			name:        "feature gate enabled but no proxy configured returns nil proxy (no env)",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			}),
			reqURL: httpsURL,
		},
		{
			name:        "feature gate enabled with httpsProxy configured returns proxy for https request",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL:       httpsURL,
			wantProxyURL: "http://proxy.corp.example.com:3128",
		},
		{
			name:        "feature gate enabled with httpProxy configured returns proxy for http request",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL:       httpURL,
			wantProxyURL: "http://proxy.corp.example.com:3128",
		},
		{
			name:        "httpsProxy configured does not proxy http requests",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL: httpURL,
		},
		{
			name:        "httpProxy configured does not proxy https requests",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL: httpsURL,
		},
		{
			name:        "noProxy match returns nil proxy",
			featureGate: enabledGate,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
						NoProxy:    []string{httpURL.Host},
					},
				},
			}),
			reqURL: httpsURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("NO_PROXY", "")

			proxy, err := ResolveProxy(tt.featureGate, tt.authLister)
			if err != nil {
				t.Fatalf("unexpected resolve error: %v", err)
			}
			proxyURL, err := proxy.ProxyFunc()(tt.reqURL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var gotProxyURL string
			if proxyURL != nil {
				gotProxyURL = proxyURL.String()
			}
			if gotProxyURL != tt.wantProxyURL {
				t.Errorf("proxy URL = %q, want %q", gotProxyURL, tt.wantProxyURL)
			}
		})
	}
}

func newOperatorAuthLister(auth *operatorv1.Authentication) operatorv1listers.AuthenticationLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if auth != nil {
		_ = indexer.Add(auth)
	}
	return operatorv1listers.NewAuthenticationLister(indexer)
}

type errorAuthLister struct {
	err error
}

func newErrorAuthLister(err error) operatorv1listers.AuthenticationLister {
	return &errorAuthLister{err}
}

func (l *errorAuthLister) List(_ labels.Selector) ([]*operatorv1.Authentication, error) {
	return nil, l.err
}

func (l *errorAuthLister) Get(_ string) (*operatorv1.Authentication, error) {
	return nil, l.err
}

func expectedNoProxy(extra ...string) string {
	entries := sets.New[string](".cluster.local", ".svc", "127.0.0.1", "localhost")
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		entries.Insert(host)
	}
	entries.Insert(extra...)
	return strings.Join(sets.List(entries), ",")
}
