package oauth

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/datasync"
	"github.com/openshift/library-go/pkg/crypto"
)

func Test_convertProviderConfigToIDPData(t *testing.T) {
	tmpDir := t.TempDir()
	ca, err := crypto.MakeSelfSignedCA(path.Join(tmpDir, "cert.crt"), path.Join(tmpDir, "key.key"), "", "testCA", time.Hour*24*5)
	require.NoError(t, err)
	serverConfig, err := ca.MakeServerCert(sets.New("localhost", "127.0.0.1", "::1"), time.Hour*24)
	require.NoError(t, err)
	certPEM, keyPEM, err := serverConfig.GetPEMBytes()
	require.NoError(t, err)

	tests := []struct {
		name                 string
		providerConfig       *configv1.IdentityProviderConfig
		configMap            *corev1.ConfigMap
		secret               *corev1.Secret
		want                 *idpData
		oidcDiscoveryContent string
		wantErr              bool
	}{
		{
			name: "htpasswd idp",
			providerConfig: &configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeHTPasswd,
				HTPasswd: &configv1.HTPasswdIdentityProvider{
					FileData: configv1.SecretNameReference{
						Name: "somesecret",
					},
				},
			},
			want: &idpData{
				challenge: true,
				login:     true,
				provider: &osinv1.HTPasswdPasswordIdentityProvider{
					File: "/var/config/user/idp/0/secret/v4-0-config-user-idp-0-file-data/htpasswd",
				},
			},
		},
		{
			name: "OIDC basic idp - no groups",
			providerConfig: &configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeOpenID,
				OpenID: &configv1.OpenIDIdentityProvider{
					ClientID: "someclientid",
					ClientSecret: configv1.SecretNameReference{
						Name: "clientsecretsecret",
					},
					CA: configv1.ConfigMapNameReference{
						Name: "customca",
					},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{Name: "customca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca.crt": getCertBytesFromCAConfig(t, ca)},
			},
			secret: &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{Name: "clientsecretsecret", Namespace: "openshift-config"},
				Data:       map[string][]byte{"clientSecret": []byte("veeery_random")},
			},
			oidcDiscoveryContent: `{
				"issuer": "${OIDC_URL}",
				"authorization_endpoint": "${OIDC_URL}/authorization",
				"token_endpoint": "${OIDC_URL}/token"
				}`,
			want: &idpData{
				challenge: false,
				login:     true,
				provider: &osinv1.OpenIDIdentityProvider{
					ClientID: "someclientid",
					ClientSecret: configv1.StringSource{
						StringSourceSpec: configv1.StringSourceSpec{
							File: "/var/config/user/idp/0/secret/v4-0-config-user-idp-0-client-secret/clientSecret",
						},
					},
					CA: "/var/config/user/idp/0/configMap/v4-0-config-user-idp-0-ca/ca.crt",
					URLs: osinv1.OpenIDURLs{
						Authorize: "${OIDC_URL}/authorization",
						Token:     "${OIDC_URL}/token",
					},
					Claims: osinv1.OpenIDClaims{
						ID:     []string{"sub"},
						Groups: []string{},
					},
				},
			},
		}, {
			name: "OIDC basic idp with groups",
			providerConfig: &configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeOpenID,
				OpenID: &configv1.OpenIDIdentityProvider{
					ClientID: "someclientid",
					ClientSecret: configv1.SecretNameReference{
						Name: "clientsecretsecret",
					},
					CA: configv1.ConfigMapNameReference{
						Name: "customca",
					},
					Claims: configv1.OpenIDClaims{Groups: []configv1.OpenIDClaim{"groups", "idpgroups"}},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{Name: "customca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca.crt": getCertBytesFromCAConfig(t, ca)},
			},
			secret: &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{Name: "clientsecretsecret", Namespace: "openshift-config"},
				Data:       map[string][]byte{"clientSecret": []byte("veeery_random")},
			},
			oidcDiscoveryContent: `{
				"issuer": "${OIDC_URL}",
				"authorization_endpoint": "${OIDC_URL}/authorization",
				"token_endpoint": "${OIDC_URL}/token"
				}`,
			want: &idpData{
				challenge: false,
				login:     true,
				provider: &osinv1.OpenIDIdentityProvider{
					ClientID: "someclientid",
					ClientSecret: configv1.StringSource{
						StringSourceSpec: configv1.StringSourceSpec{
							File: "/var/config/user/idp/0/secret/v4-0-config-user-idp-0-client-secret/clientSecret",
						},
					},
					CA: "/var/config/user/idp/0/configMap/v4-0-config-user-idp-0-ca/ca.crt",
					URLs: osinv1.OpenIDURLs{
						Authorize: "${OIDC_URL}/authorization",
						Token:     "${OIDC_URL}/token",
					},
					Claims: osinv1.OpenIDClaims{
						ID:     []string{"sub"},
						Groups: []string{"groups", "idpgroups"},
					},
				},
			},
		},
		{
			name: "OIDC basic idp - bogus discovery info",
			providerConfig: &configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeOpenID,
				OpenID: &configv1.OpenIDIdentityProvider{
					ClientID: "someclientid",
					ClientSecret: configv1.SecretNameReference{
						Name: "clientsecretsecret",
					},
					CA: configv1.ConfigMapNameReference{
						Name: "customca",
					},
					Claims: configv1.OpenIDClaims{Groups: []configv1.OpenIDClaim{"groups"}},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{Name: "customca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca.crt": getCertBytesFromCAConfig(t, ca)},
			},
			secret: &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{Name: "clientsecretsecret", Namespace: "openshift-config"},
				Data:       map[string][]byte{"clientSecret": []byte("veeery_random")},
			},
			oidcDiscoveryContent: `<html><head><title>nope!</title></head></html>`,
			wantErr:              true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncData := datasync.NewConfigSyncData()

			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.configMap != nil {
				require.NoError(t, indexer.Add(tt.configMap))
			}
			if tt.secret != nil {
				require.NoError(t, indexer.Add(tt.secret))
			}
			cmLister := corelistersv1.NewConfigMapLister(indexer)
			secretLister := corelistersv1.NewSecretLister(indexer)

			var server *httptest.Server
			if len(tt.oidcDiscoveryContent) > 0 {
				server, err = newTestHTTPSServer(certPEM, keyPEM, tt.oidcDiscoveryContent)
				require.NoError(t, err)
				defer server.Close()

				tt.providerConfig.OpenID.Issuer = server.URL
			}

			got, err := convertProviderConfigToIDPData(cmLister, secretLister, tt.providerConfig, syncData, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertProviderConfigToIDPData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want == nil {
				if got != nil {
					t.Errorf("expected no IdP data, got { challenge: %v login: %v provider %#v }", got.challenge, got.login, got.provider)
					return
				}
				return
			}

			if obj, ok := tt.want.provider.(*osinv1.OpenIDIdentityProvider); server != nil && ok {
				injectServerURLToOIDCExpected(obj, server.URL)
			}

			if got.challenge == tt.want.challenge &&
				got.login == tt.want.login &&
				!reflect.DeepEqual(got.provider.DeepCopyObject(), tt.want.provider.DeepCopyObject()) {
				t.Errorf(
					"convertProviderConfigToIDPData() =\n got challenge: %v;\n got login %v;\n\n WANT\n\n want challenge: %v;\n want login %v;\n\n provider diff %s",
					got.challenge, got.login,
					tt.want.challenge, tt.want.login,
					cmp.Diff(got.provider, tt.want.provider),
				)
			}
		})
	}
}

func newTestHTTPSServer(certPEM, keyPEM []byte, content string) (*httptest.Server, error) {
	// use a byte slice reference to replace with a valid content with replaced
	// server URLs once the server is started
	var postedContent []byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(postedContent)
	}))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("error parsing server cert/key pair: %s", err)
	}

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server.StartTLS()

	// now we can replace the OIDC urls with valid server URL strings
	postedContent = []byte(strings.ReplaceAll(content, "${OIDC_URL}", server.URL))
	return server, nil
}

func getCertBytesFromCAConfig(t *testing.T, caConfig *crypto.CA) string {
	certBytes, _, err := caConfig.Config.GetPEMBytes()
	require.NoError(t, err)
	return string(certBytes)
}

func injectServerURLToOIDCExpected(provider *osinv1.OpenIDIdentityProvider, serverURL string) {
	provider.URLs.Authorize = strings.Replace(provider.URLs.Authorize, "${OIDC_URL}", serverURL, 1)
	provider.URLs.Token = strings.Replace(provider.URLs.Token, "${OIDC_URL}", serverURL, 1)
	provider.URLs.UserInfo = strings.Replace(provider.URLs.UserInfo, "${OIDC_URL}", serverURL, 1)
}
