package operator

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
)

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
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected extractIdPURLs() result (-want +got):\n%s", diff)
			}
		})
	}
}
