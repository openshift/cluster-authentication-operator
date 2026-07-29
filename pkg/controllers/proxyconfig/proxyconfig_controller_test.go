package proxyconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

func Test_checkProxyConfig(t *testing.T) {
	endpoint := "https://proxy.testing.com:443"
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	goodHTTPClient := &http.Client{
		Transport: &workingHTTPRoundTripper{},
	}
	badHTTPClient := &http.Client{
		Transport: &faultyHTTPRoundTripper{},
	}
	tests := []struct {
		name               string
		noProxy            string
		clientWithProxy    *http.Client
		clientWithoutProxy *http.Client
		wantErr            error
	}{
		{
			name:            "good proxy config with endpoint not matching noProxy",
			clientWithProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching noProxy",
			noProxy:            "proxy.testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching domain in noProxy",
			noProxy:            "testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "endpoint matching noProxy is unreachable with/without proxy",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, "testing.com", endpoint, endpoint),
		},
		{
			name:               "endpoint matching noProxy is reachable with proxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %q returned 404", endpoint, "proxy.testing.com", endpoint),
		},
		{
			name:               "endpoint not matching noProxy is reachable without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(\"\") with error: %q returned 404", endpoint, endpoint),
		},
		{
			name:               "endpoint not matching noProxy is unreachable with/without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, endpoint, endpoint),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProxyConfig(context.TODO(), endpointURL, tt.noProxy, tt.clientWithProxy, tt.clientWithoutProxy)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("checkProxyConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_extractIdPURLs(t *testing.T) {
	tests := []struct {
		name string
		idps []configv1.IdentityProvider
		want []string
	}{
		{
			name: "no providers",
		},
		{
			name: "OpenID appends well-known path",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeOpenID,
					OpenID: &configv1.OpenIDIdentityProvider{Issuer: "https://sso.example.com/"},
				},
			}},
			want: []string{"https://sso.example.com/.well-known/openid-configuration"},
		},
		{
			name: "GitHub with custom hostname",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitHub,
					GitHub: &configv1.GitHubIdentityProvider{Hostname: "github.corp.example.com"},
				},
			}},
			want: []string{"https://github.corp.example.com"},
		},
		{
			name: "GitHub without hostname defaults to github.com",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitHub,
					GitHub: &configv1.GitHubIdentityProvider{},
				},
			}},
			want: []string{"https://github.com"},
		},
		{
			name: "GitLab",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitLab,
					GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
				},
			}},
			want: []string{"https://gitlab.example.com"},
		},
		{
			name: "Keystone",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:     configv1.IdentityProviderTypeKeystone,
					Keystone: &configv1.KeystoneIdentityProvider{OAuthRemoteConnectionInfo: configv1.OAuthRemoteConnectionInfo{URL: "https://keystone.example.com"}},
				},
			}},
			want: []string{"https://keystone.example.com"},
		},
		{
			name: "BasicAuth",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:      configv1.IdentityProviderTypeBasicAuth,
					BasicAuth: &configv1.BasicAuthIdentityProvider{OAuthRemoteConnectionInfo: configv1.OAuthRemoteConnectionInfo{URL: "https://auth.example.com"}},
				},
			}},
			want: []string{"https://auth.example.com"},
		},
		{
			name: "Google uses fixed endpoint",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGoogle,
					Google: &configv1.GoogleIdentityProvider{ClientID: "id"},
				},
			}},
			want: []string{"https://accounts.google.com"},
		},
		{
			name: "LDAP is skipped",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type: configv1.IdentityProviderTypeLDAP,
					LDAP: &configv1.LDAPIdentityProvider{URL: "ldap://ldap.example.com"},
				},
			}},
		},
		{
			name: "HTPasswd is skipped",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:     configv1.IdentityProviderTypeHTPasswd,
					HTPasswd: &configv1.HTPasswdIdentityProvider{},
				},
			}},
		},
		{
			name: "RequestHeader is skipped",
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:          configv1.IdentityProviderTypeRequestHeader,
					RequestHeader: &configv1.RequestHeaderIdentityProvider{},
				},
			}},
		},
		{
			name: "multiple providers",
			idps: []configv1.IdentityProvider{
				{IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeOpenID,
					OpenID: &configv1.OpenIDIdentityProvider{Issuer: "https://sso.example.com"},
				}},
				{IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitLab,
					GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
				}},
				{IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:     configv1.IdentityProviderTypeHTPasswd,
					HTPasswd: &configv1.HTPasswdIdentityProvider{},
				}},
			},
			want: []string{
				"https://sso.example.com/.well-known/openid-configuration",
				"https://gitlab.example.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIdPURLs(&configv1.OAuth{
				Spec: configv1.OAuthSpec{IdentityProviders: tt.idps},
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractIdPURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateIdPConnectivity(t *testing.T) {
	tests := []struct {
		name        string
		idps        []configv1.IdentityProvider
		client      *http.Client
		wantReason  string
		wantMessage string
	}{
		{
			name:   "all reachable emits no event",
			client: &http.Client{Transport: &workingHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitLab,
					GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
				},
			}},
		},
		{
			name:   "unreachable emits warning",
			client: &http.Client{Transport: &faultyHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{{
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitLab,
					GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
				},
			}},
			wantReason:  "IdPEndpointUnreachable",
			wantMessage: `IdP endpoints unreachable through proxy: "https://gitlab.example.com" returned 404`,
		},
		{
			name:   "multiple unreachable emits single event",
			client: &http.Client{Transport: &faultyHTTPRoundTripper{}},
			idps: []configv1.IdentityProvider{
				{IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeGitLab,
					GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
				}},
				{IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type:   configv1.IdentityProviderTypeOpenID,
					OpenID: &configv1.OpenIDIdentityProvider{Issuer: "https://sso.example.com"},
				}},
			},
			wantReason:  "IdPEndpointUnreachable",
			wantMessage: `IdP endpoints unreachable through proxy: "https://gitlab.example.com" returned 404; "https://sso.example.com/.well-known/openid-configuration" returned 404`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(&configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.OAuthSpec{IdentityProviders: tt.idps},
			}); err != nil {
				t.Fatal(err)
			}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			p := &proxyConfigChecker{
				oauthLister: configv1listers.NewOAuthLister(indexer),
			}

			p.validateIdPConnectivity(context.Background(), recorder, tt.client, "", "", "")

			recordedEvents := recorder.Events()
			if tt.wantReason == "" {
				if len(recordedEvents) > 0 {
					t.Fatalf("expected no events but got %d: %v", len(recordedEvents), recordedEvents)
				}
				return
			}
			if len(recordedEvents) != 1 {
				t.Fatalf("expected 1 event but got %d", len(recordedEvents))
			}
			if recordedEvents[0].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", recordedEvents[0].Reason, tt.wantReason)
			}
			if recordedEvents[0].Message != tt.wantMessage {
				t.Errorf("message = %q, want %q", recordedEvents[0].Message, tt.wantMessage)
			}
		})
	}
}

func Test_validateIdPConnectivity_hashDedup(t *testing.T) {
	idps := []configv1.IdentityProvider{{
		IdentityProviderConfig: configv1.IdentityProviderConfig{
			Type:   configv1.IdentityProviderTypeGitLab,
			GitLab: &configv1.GitLabIdentityProvider{URL: "https://gitlab.example.com"},
		},
	}}
	oauthConfig := &configv1.OAuth{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec:       configv1.OAuthSpec{IdentityProviders: idps},
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := indexer.Add(oauthConfig); err != nil {
		t.Fatal(err)
	}

	t.Run("second call with same config skips validation", func(t *testing.T) {
		recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		p := &proxyConfigChecker{
			oauthLister: configv1listers.NewOAuthLister(indexer),
		}

		reachable := &http.Client{Transport: &workingHTTPRoundTripper{}}
		p.validateIdPConnectivity(context.Background(), recorder, reachable, "http://proxy:3128", "", "")
		if len(recorder.Events()) != 0 {
			t.Fatalf("first call should emit no events for reachable endpoints, got %d", len(recorder.Events()))
		}

		followupRecorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		unreachable := &http.Client{Transport: &faultyHTTPRoundTripper{}}
		p.validateIdPConnectivity(context.Background(), followupRecorder, unreachable, "http://proxy:3128", "", "")
		if len(followupRecorder.Events()) != 0 {
			t.Fatalf("second call with same config should skip validation, got %d events", len(followupRecorder.Events()))
		}
	})

	t.Run("hash not saved on failure allows retry", func(t *testing.T) {
		recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		p := &proxyConfigChecker{
			oauthLister: configv1listers.NewOAuthLister(indexer),
		}

		unreachable := &http.Client{Transport: &faultyHTTPRoundTripper{}}
		p.validateIdPConnectivity(context.Background(), recorder, unreachable, "http://proxy:3128", "", "")
		if len(recorder.Events()) != 1 {
			t.Fatalf("expected 1 event on failure, got %d", len(recorder.Events()))
		}

		followupRecorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		p.validateIdPConnectivity(context.Background(), followupRecorder, unreachable, "http://proxy:3128", "", "")
		if len(followupRecorder.Events()) != 1 {
			t.Fatalf("expected 1 event on retry after failure, got %d", len(followupRecorder.Events()))
		}
	})
}

type workingHTTPRoundTripper struct{}

func (s *workingHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

type faultyHTTPRoundTripper struct{}

func (s *faultyHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404}, nil
}
