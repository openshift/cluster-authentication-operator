package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	features "github.com/openshift/api/features"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	operatorversionedclient "github.com/openshift/client-go/operator/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/stretchr/testify/require"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/golang-jwt/jwt/v5"
)

const (
	oidcClientId      = "admin-cli"
	oidcGroupsClaim   = "groups"
	oidcUsernameClaim = "email"

	kasNamespace = "openshift-kube-apiserver"
)

type testClient struct {
	t *testing.T

	kubeConfig            *rest.Config
	kubeClient            *kubernetes.Clientset
	configClient          *configclient.Clientset
	operatorConfigClient  *operatorversionedclient.Clientset
	oauthClient           oauthclient.Interface
	routeClient           routeclient.Interface
	apiregistrationClient apiregistrationclient.Interface
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

type expectedClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Type  string `json:"typ"`
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

	auth, err := tc.configClient.ConfigV1().Authentications().Get(testCtx, "cluster", metav1.GetOptions{})
	require.NoError(tc.t, err, "failed to get authentication/cluster")
	require.NotNil(tc.t, auth)

	// ==============
	// Setup Keycloak
	// ==============

	var kcClient *test.KeycloakClient
	if keycloakURL := os.Getenv("E2E_KEYCLOAK_URL"); len(keycloakURL) > 0 {
		// this case is used for development purposes; OIDC must have already been set up
		if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
			tc.t.Skipf("using an existing keycloak deployment via E2E_KEYCLOAK_URL requires OIDC already set up, but auth type is '%s'", auth.Spec.Type)
		}

		t.Logf("will use existing keycloak deployment at URL: %s", keycloakURL)
		kcClient = tc.setupKeycloakClient(testCtx, keycloakURL)

	} else {
		// this test assumes we're starting from built-in OAuth
		switch auth.Spec.Type {
		case configv1.AuthenticationTypeNone, configv1.AuthenticationTypeOIDC:
			tc.t.Skipf("auth type must be IntegratedOAuth or ''; was '%s'", auth.Spec.Type)
		}

		var idpName string
		var cleanups []func()
		kcClient, idpName, cleanups = test.AddKeycloakIDP(tc.t, tc.kubeConfig, true)
		t.Logf("keycloak Admin URL: %s", kcClient.AdminURL())

		// default-ingress-cert is copied to openshift-config and used as the CA for the IdP
		// see test/library/idpdeployment.go:334
		caBundleName := idpName + "-ca"

		// all OAuth resources must be present
		tc.validateOAuthResources(testCtx, false)

		// update the authentication CR with the external OIDC configuration
		c := tc.updateAuthForOIDC(testCtx, auth, kcClient.IssuerURL(), idpName, caBundleName)
		cleanups = append(cleanups, c...)

		kasRevision := tc.validateKASConfig(testCtx)

		tc.validateAuthConfigJSON(testCtx, kcClient.IssuerURL(), caBundleName, kasRevision)

		// now all OAuth resources must be missing
		tc.validateOAuthResources(testCtx, true)

		cleanups = append(cleanups, func() {
			// after cleanup, all OAuth resources must be present again
			tc.validateOAuthResources(testCtx, false)
		})

		defer test.IDPCleanupWrapper(func() {
			for _, c := range cleanups {
				c()
			}
		})()
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

	// ========================================
	// Validate the contents of the OIDC tokens
	// ========================================
	accessToken, idToken, err := parseOIDCTokens(kcClient.IssuerURL(), authResponse.AccessToken, authResponse.IdToken)
	require.NoError(t, err)
	require.NotNil(t, accessToken)
	require.NotNil(t, idToken)

	actualAccessTokenClaims := accessToken.Claims.(*expectedClaims)
	require.True(t, accessToken.Valid)
	require.Equal(t, kcClient.IssuerURL(), actualAccessTokenClaims.Issuer)
	require.Equal(t, email, actualAccessTokenClaims.Email)
	require.Equal(t, "Bearer", actualAccessTokenClaims.Type)

	actualIDTokenClaims := idToken.Claims.(*expectedClaims)
	require.True(t, idToken.Valid)
	require.Equal(t, kcClient.IssuerURL(), actualIDTokenClaims.Issuer)
	require.Equal(t, email, actualIDTokenClaims.Email)
	require.Equal(t, "ID", actualIDTokenClaims.Type)
	require.Equal(t, jwt.ClaimStrings{oidcClientId}, actualIDTokenClaims.Audience)

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

	tc.oauthClient, err = oauthclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.routeClient, err = routeclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	tc.apiregistrationClient, err = apiregistrationclient.NewForConfig(tc.kubeConfig)
	if err != nil {
		return nil, err
	}

	return tc, nil
}

func parseOIDCTokens(issuerURL string, accessToken, idToken string) (*jwt.Token, *jwt.Token, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// grab openid-configuration JSON which contains the URL of the provider's JWKS
	resp, err := client.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, nil, fmt.Errorf("could not get issuer OpenID well-known configuration: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse well-known response body: %v", err)
	}

	type openidConfig struct {
		JwksURL string `json:"jwks_uri"`
	}

	var oidcConfig openidConfig
	if err := json.Unmarshal(respBytes, &oidcConfig); err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal OpenID config: %v", err)
	}

	// grab the provider's JWKS which contains the pubkey to verify token signatures
	resp, err = client.Get(oidcConfig.JwksURL)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get issuer OpenID well-known JWKS configuration: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse well-known JWKS response body: %v", err)
	}

	type jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			Use string `json:"use"`
			KTY string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	var issuerJWKS jwks
	if err := json.Unmarshal(respBytes, &issuerJWKS); err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal JWKS: %v", err)
	}

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		for _, key := range issuerJWKS.Keys {
			if key.KID == token.Header["kid"] {
				switch key.Alg {
				case "RS256":
					n, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						return nil, fmt.Errorf("could not decode N: %v", err)
					}
					e, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						return nil, fmt.Errorf("could not decode E: %v", err)
					}

					pubkey := &rsa.PublicKey{
						N: new(big.Int).SetBytes(n),
						E: int(new(big.Int).SetBytes(e).Int64()),
					}

					return pubkey, nil
				}

				return nil, fmt.Errorf("unexpected signing algorithm for key '%s': %s", key.KID, key.Alg)
			}
		}

		return nil, fmt.Errorf("could not find an RSA key for signing use in the provided JWKS")
	}

	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &expectedClaims{}, keyfunc)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse access token: %v", err)
	}

	parsedIDToken, err := jwt.ParseWithClaims(idToken, &expectedClaims{}, keyfunc)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse ID token: %v", err)
	}

	return parsedAccessToken, parsedIDToken, nil
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

func (tc *testClient) updateAuthForOIDC(ctx context.Context, auth *configv1.Authentication, idpURL, idpName, caBundleName string) (cleanups []func()) {
	tc.t.Log("will update auth CR for OIDC")

	// TODO add more claims, rules, etc
	origSpec := (*auth).Spec.DeepCopy()

	// first, make an invalid change to the Auth CR and make sure that the operator will become degraded
	invalidCABundleName := caBundleName + "_invalid"
	auth.Spec = getAuthSpecForOIDCProvider(idpName, idpURL, invalidCABundleName)

	var err error
	auth, err = tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		auth, err = tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while retrieving fresh object: %v", auth.Name, err)
		}

		auth.Spec = *origSpec
		if _, err := tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{}); err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while updating object: %v", auth.Name, err)
		}
	})
	require.NoError(tc.t, err, "failed to update authentication/cluster")

	// test that the auth CR has been indeed updated successfully
	require.NotEqual(tc.t, origSpec.Type, auth.Spec.Type)
	require.Equal(tc.t, configv1.AuthenticationTypeOIDC, auth.Spec.Type)
	require.NotEmpty(tc.t, auth.Spec.OIDCProviders)
	require.Equal(tc.t, invalidCABundleName, auth.Spec.OIDCProviders[0].Issuer.CertificateAuthority.Name)

	// however, the operator must be degraded as the change is invalid
	tc.t.Logf("will wait for auth operator to become degraded")
	err = test.WaitForClusterOperatorDegraded(tc.t, tc.configClient.ConfigV1(), "authentication")
	require.NoError(tc.t, err, "failed to wait for cluster operator to get degraded")

	// therefore no auth-config CM should exist in openshift-config-managed
	_, err = tc.kubeClient.CoreV1().ConfigMaps("openshift-config-managed").Get(ctx, "auth-config", metav1.GetOptions{})
	require.True(tc.t, errors.IsNotFound(err), fmt.Sprintf("get openshift-config-managed/auth-config error: %v", err))

	// now correct the invalid URL and make sure the operator becomes available
	auth, err = tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(tc.t, err, "failed to get authentication/cluster")
	auth.Spec = getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName)

	// record current KAS revision
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(tc.t, err, "failed to get kubeapiserver/cluster")
	kasOriginalRevision := kas.Status.LatestAvailableRevision

	auth, err = tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		// add a wait for KAS rollout to the cleanups because at this stage we have had a valid OIDC config
		// which needs to be rolled back
		kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while retrieving kubeapiservers/cluster: %v", auth.Name, err)
		}
		kasOriginalCleanupRevision := kas.Status.LatestAvailableRevision

		if kasOriginalCleanupRevision > kasOriginalRevision {
			// a new rollout occured because of this test; cleanup will therefore cause another rollout
			tc.t.Log("cleanup waiting for KAS rollout for original auth config")
			if err := test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalCleanupRevision); err != nil {
				tc.t.Fatalf("cleanup failed for authentication '%s' while waiting for KAS rollout: %v", auth.Name, err)
			}
		}
	})
	require.NoError(tc.t, err, "failed to update authentication/cluster")

	// the issuer URL should now be the valid one
	require.Equal(tc.t, idpURL, auth.Spec.OIDCProviders[0].Issuer.URL)

	tc.t.Logf("will wait for auth operator to become available again")
	err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(tc.t, tc.configClient.ConfigV1(), "authentication")
	require.NoError(tc.t, err, "failed to wait for cluster operator to become available")

	tc.t.Log("will wait for KAS rollout for new auth config")
	err = test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
	require.NoError(tc.t, err, "failed to wait for KAS rollout")

	// once KAS rollout has been completed, the CAO will turn Available=False/Progressing=False/Degraded=False
	err = test.WaitForClusterOperatorStatus(tc.t, tc.configClient.ConfigV1(), "authentication", configv1.ConditionFalse, configv1.ConditionFalse, configv1.ConditionFalse, "")
	require.NoError(tc.t, err, "failed to wait for cluster operator to reach Available=False/Progressing=False/Degraded=False")

	return
}

func getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName string) configv1.AuthenticationSpec {
	return configv1.AuthenticationSpec{
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
}

func (tc *testClient) validateKASConfig(ctx context.Context) int32 {
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(tc.t, err)

	var observedConfig map[string]interface{}
	err = json.Unmarshal(kas.Spec.ObservedConfig.Raw, &observedConfig)
	require.NoError(tc.t, err)

	apiServerArguments := observedConfig["apiServerArguments"].(map[string]interface{})

	require.Nil(tc.t, apiServerArguments["authentication-token-webhook-config-file"])
	require.Nil(tc.t, apiServerArguments["authentication-token-webhook-version"])
	require.Nil(tc.t, observedConfig["authConfig"])

	authConfigArg := apiServerArguments["authentication-config"].([]interface{})
	require.NotEmpty(tc.t, authConfigArg)
	require.Equal(tc.t, authConfigArg[0].(string), "/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json")

	return kas.Status.LatestAvailableRevision
}

func (tc *testClient) validateAuthConfigJSON(ctx context.Context, idpURL, caBundleName string, kasRevision int32) {
	certData := ""
	if len(caBundleName) > 0 {
		cm, err := tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Get(ctx, caBundleName, metav1.GetOptions{})
		require.NoError(tc.t, err)
		certData = cm.Data["ca-bundle.crt"]
	}

	expectedAuthConfigJSON := fmt.Sprintf(`{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"%s","certificateAuthority":"%s","audiences":[%s],"audienceMatchPolicy":"MatchAny"},"claimMappings":{"username":{"claim":"%s","prefix":"%s"},"groups":{"claim":"%s","prefix":"%s"},"uid":{}}}]}`,
		idpURL,
		strings.ReplaceAll(certData, "\n", "\\n"),
		strings.Join([]string{fmt.Sprintf(`"%s"`, oidcClientId)}, ","),
		oidcUsernameClaim,
		"",
		oidcGroupsClaim,
		"",
	)

	for _, cm := range []struct {
		ns   string
		name string
	}{
		{"openshift-config-managed", "auth-config"},
		{"openshift-kube-apiserver", "auth-config"},
		{"openshift-kube-apiserver", fmt.Sprintf("auth-config-%d", kasRevision)},
	} {
		actualCM, err := tc.kubeClient.CoreV1().ConfigMaps(cm.ns).Get(ctx, cm.name, metav1.GetOptions{})
		require.NoError(tc.t, err)
		require.Equal(tc.t, expectedAuthConfigJSON, actualCM.Data["auth-config.json"], "unexpected auth-config.json contents in %s/%s", actualCM.Namespace, actualCM.Name)
	}
}

type namespacedObject struct {
	namespace string
	name      string
}

func (o *namespacedObject) String() string {
	return fmt.Sprintf("%s/%s", o.namespace, o.name)
}

func (tc *testClient) validateOAuthResources(ctx context.Context, requireMissing bool) {
	// deployments
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "oauth-openshift"},
		{"openshift-oauth-apiserver", "apiserver"},
	} {
		deployment, err := tc.kubeClient.AppsV1().Deployments(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		require.NoError(tc.t, err)
		if requireMissing {
			require.Zero(tc.t, deployment.Status.AvailableReplicas, "deployment %s must have 0 available replicas", obj)
		} else {
			require.Equal(tc.t, *deployment.Spec.Replicas, deployment.Status.AvailableReplicas, "deployment %s must have available replicas", obj)
		}
	}

	// configmaps
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "v4-0-config-system-metadata"},
		{"openshift-authentication", "v4-0-config-system-trusted-ca-bundle"},
		{"openshift-authentication", "v4-0-config-system-service-ca"},
		{"openshift-authentication", "v4-0-config-system-cliconfig"},
	} {
		cm, err := tc.kubeClient.CoreV1().ConfigMaps(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "configmap %s must be missing", obj)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, cm, "configmap %s must not be nil", obj)
		}
	}

	// secrets
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "v4-0-config-system-ocp-branding-template"},
		{"openshift-authentication", "v4-0-config-system-session"},
	} {
		secret, err := tc.kubeClient.CoreV1().Secrets(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "secret %s must be missing", obj)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, secret, "secret %s must not be nil", obj)
		}
	}

	// oauthclients
	for _, name := range []string{
		"openshift-browser-client",
		"openshift-challenging-client",
		"openshift-cli-client",
	} {
		oc, err := tc.oauthClient.OauthV1().OAuthClients().Get(ctx, name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "oauthclient %s must be missing", name)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, oc, "oauthclient %s must not be nil", name)
		}
	}

	// services
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "oauth-openshift"},
	} {
		service, err := tc.kubeClient.CoreV1().Services(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "service %s must be missing", obj)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, service, "service %s must not be nil", obj)
		}
	}

	// routes
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "oauth-openshift"},
	} {
		route, err := tc.routeClient.RouteV1().Routes(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "route %s must be missing", obj)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, route, "route %s must not be nil", obj)
		}

		// ingress status
		ingress, err := tc.configClient.ConfigV1().Ingresses().Get(ctx, "cluster", metav1.GetOptions{})
		require.NoError(tc.t, err)
		found := false
		for _, route := range ingress.Status.ComponentRoutes {
			if route.Name == obj.name && route.Namespace == obj.namespace {
				found = true
				break
			}
		}

		if requireMissing {
			require.False(tc.t, found, "route %s must be missing from ingress status", obj)
		} else {
			require.True(tc.t, found, "route %s must exist in ingress status", obj)
		}
	}

	// APIServices
	for _, name := range []string{
		"v1.oauth.openshift.io",
		"v1.user.openshift.io",
	} {
		apiservice, err := tc.apiregistrationClient.ApiregistrationV1().APIServices().Get(ctx, name, metav1.GetOptions{})
		if requireMissing {
			require.True(tc.t, errors.IsNotFound(err), "apiservice %s must be missing", name)
		} else {
			require.NoError(tc.t, err)
			require.NotNil(tc.t, apiservice, "apiservice %s must not be nil", name)
		}
	}
}
