package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	features "github.com/openshift/api/features"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorversionedclient "github.com/openshift/client-go/operator/clientset/versioned"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	oidcClientId      = "admin-cli"
	oidcGroupsClaim   = "groups"
	oidcUsernameClaim = "email"

	kasNamespace = "openshift-kube-apiserver"
)

type testClient struct {
	t *testing.T

	kubeConfig           *rest.Config
	kubeClient           *kubernetes.Clientset
	configClient         *configclient.Clientset
	operatorConfigClient *operatorversionedclient.Clientset
}

type oidcAuthResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not_before_policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func TestExternalOIDCWithKeycloak(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := newTestClient(t)
	require.NoError(t, err)

	// ===============================
	// Check ExternalOIDC feature gate
	// ===============================

	featureGates, err := tc.configClient.ConfigV1().FeatureGates().Get(testCtx, "cluster", metav1.GetOptions{})
	require.NoError(tc.t, err)

	if len(featureGates.Status.FeatureGates) != 1 {
		// fail test if there are multiple feature gate versions (i.e. ongoing upgrade)
		tc.t.Fatalf("multiple feature gate versions detected")
	} else {
		for _, fgDisabled := range featureGates.Status.FeatureGates[0].Disabled {
			if fgDisabled.Name == features.FeatureGateExternalOIDC {
				tc.t.Skipf("feature gate '%s' disabled", features.FeatureGateExternalOIDC)
			}
		}
	}

	// ==============
	// Setup Keycloak
	// ==============

	var kcClient *test.KeycloakClient
	if keycloakURL := os.Getenv("E2E_KEYCLOAK_URL"); len(keycloakURL) > 0 {
		t.Logf("will use existing keycloak deployment at URL: %s", keycloakURL)
		kcClient = tc.setupKeycloakClient(testCtx, keycloakURL)

	} else {
		t.Logf("no existing keycloak deployment found; will create new")
		var cleanups []func()
		kcClient, cleanups = tc.setupExternalOIDCWithKeycloak(testCtx)
		defer test.IDPCleanupWrapper(func() {
			for _, c := range cleanups {
				c()
			}
		})()
		t.Logf("keycloak Admin URL: %s", kcClient.AdminURL())
	}

	group := names.SimpleNameGenerator.GenerateName("e2e-keycloak-group-")
	err = kcClient.CreateGroup(group)
	require.NoError(t, err)

	user := names.SimpleNameGenerator.GenerateName("e2e-keycloak-user-")
	email := fmt.Sprintf("%s@test.dev", user)
	password := "password"
	err = kcClient.CreateUser(user, email, password, []string{group})
	require.NoError(t, err)

	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	formData := url.Values{
		"grant_type": []string{"password"},
		"client_id":  []string{oidcClientId},
		"scope":      []string{"openid"},
		"username":   []string{user},
		"password":   []string{password},
	}

	resp, err := httpClient.PostForm(kcClient.TokenURL(), formData)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var authResponse oidcAuthResponse
	err = json.Unmarshal(data, &authResponse)
	require.NoError(t, err)
	require.NotEmpty(t, authResponse.AccessToken)
	require.NotEmpty(t, authResponse.IdToken)

	// ==========================================
	// Test authentication via the kube-apiserver
	// ==========================================

	// create a new kube client that uses the OIDC id_token as a bearer token
	kubeConfig := rest.AnonymousClientConfig(tc.kubeConfig)
	kubeConfig.BearerToken = authResponse.IdToken
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(tc.t, err)

	// test authentication with the OIDC token using a self subject review
	ssr, err := kubeClient.AuthenticationV1().SelfSubjectReviews().Create(testCtx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(tc.t, err)
	require.NotNil(tc.t, ssr)
	require.Contains(t, ssr.Status.UserInfo.Groups, "system:authenticated")
	require.Equal(t, email, ssr.Status.UserInfo.Username)
}

func newTestClient(t *testing.T) (*testClient, error) {
	tc := &testClient{
		t:          t,
		kubeConfig: test.NewClientConfigForTest(t),
	}

	var err error
	tc.kubeClient, err = kubernetes.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.configClient, err = configclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.operatorConfigClient, err = operatorversionedclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	return tc, nil
}

func (tc *testClient) setupKeycloakClient(ctx context.Context, keycloakURL string) *test.KeycloakClient {
	transport, err := rest.TransportFor(tc.kubeConfig)
	require.NoError(tc.t, err)

	kcClient := test.KeycloakClientFor(tc.t, transport, keycloakURL, "master")
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword(oidcClientId, "", "admin", "password")
		if err != nil {
			tc.t.Logf("failed to authenticate to Keycloak: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(tc.t, err)

	return kcClient
}

func (tc *testClient) setupExternalOIDCWithKeycloak(ctx context.Context) (kcClient *test.KeycloakClient, cleanups []func()) {
	kcClient, idpName, c := test.AddKeycloakIDP(tc.t, tc.kubeConfig, true)
	cleanups = append(cleanups, c...)

	// default-ingress-cert is copied to openshift-config and used as the CA for the IdP
	// see test/library/idpdeployment.go:334
	caBundleName := idpName + "-ca"

	// update the authentication CR with the external OIDC configuration
	authConfig, c, err := tc.updateAuthForOIDC(ctx, kcClient.IssuerURL(), idpName, caBundleName)
	cleanups = append(cleanups, c...)
	require.NoError(tc.t, err)
	require.NotNil(tc.t, authConfig)
	require.Equal(tc.t, configv1.AuthenticationTypeOIDC, authConfig.Spec.Type)
	require.NotEmpty(tc.t, authConfig.Spec.OIDCProviders)

	return
}

func (tc *testClient) updateAuthForOIDC(ctx context.Context, idpURL, idpName, caBundleName string) (auth *configv1.Authentication, cleanups []func(), err error) {
	tc.t.Log("will update auth CR for OIDC")

	auth, err = tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, cleanups, fmt.Errorf("get auth cluster error: %v", err)
	}

	origSpec := auth.Spec.DeepCopy()
	auth.Spec = configv1.AuthenticationSpec{
		Type:                      configv1.AuthenticationTypeOIDC,
		WebhookTokenAuthenticator: nil,
		OIDCProviders: []configv1.OIDCProvider{
			configv1.OIDCProvider{
				Name: idpName,
				Issuer: configv1.TokenIssuer{
					URL:       idpURL,
					Audiences: []configv1.TokenAudience{oidcClientId},
					CertificateAuthority: configv1.ConfigMapNameReference{
						Name: caBundleName,
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: configv1.UsernameClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: oidcUsernameClaim,
						},
					},
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: oidcGroupsClaim,
						},
					},
				},
			},
		},
	}

	// record current KAS revision
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, cleanups, fmt.Errorf("get kubeapiserver cluster error: %v", err)
	}
	kasOriginalRevision := kas.Status.LatestAvailableRevision

	_, err = tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while retrieving kubeapiservers/cluster: %v", auth.Name, err)
		}
		kasOriginalCleanupRevision := kas.Status.LatestAvailableRevision

		auth, err = tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while retrieving fresh object: %v", auth.Name, err)
		}

		auth.Spec = *origSpec
		if _, err := tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{}); err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while updating object: %v", auth.Name, err)
		}

		if kasOriginalCleanupRevision > kasOriginalRevision {
			// a new rollout occured because of this test; cleanup will therefore cause another rollout
			tc.t.Log("cleanup waiting for KAS rollout for original auth config")
			if err := test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalCleanupRevision); err != nil {
				tc.t.Fatalf("cleanup failed for authentication '%s' while waiting for KAS rollout: %v", auth.Name, err)
			}
		}
	})
	if err != nil {
		return nil, cleanups, fmt.Errorf("auth apply error: %v", err)
	}

	tc.t.Log("will wait for KAS rollout for new auth config")
	err = test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
	if err != nil {
		return nil, cleanups, fmt.Errorf("KAS rollout wait error: %v", err)
	}

	return
}
