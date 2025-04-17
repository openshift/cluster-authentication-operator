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
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/golang-jwt/jwt/v5"
)

const (
	oidcClientId     = "admin-cli"
	oidcGroupsClaim  = "groups"
	oidcGroupsPrefix = ""
)

type testClient struct {
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
	Email             string `json:"email"`
	Type              string `json:"typ"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
}

func TestExternalOIDCWithKeycloak(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := newTestClient(t)
	require.NoError(t, err)

	featureGates, err := tc.configClient.ConfigV1().FeatureGates().Get(testCtx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	if len(featureGates.Status.FeatureGates) != 1 {
		// fail test if there are multiple feature gate versions (i.e. ongoing upgrade)
		t.Fatalf("multiple feature gate versions detected")
	} else {
		for _, fgDisabled := range featureGates.Status.FeatureGates[0].Disabled {
			if fgDisabled.Name == features.FeatureGateExternalOIDC {
				t.Skipf("feature gate '%s' disabled", features.FeatureGateExternalOIDC)
			}
		}
	}

	// auth resource cleanup
	var cleanups []func()
	defer test.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	auth := tc.getAuth(t, testCtx)
	origAuthSpec := (*auth).Spec.DeepCopy()
	cleanups = append(cleanups, func() {
		kasOriginalRevision := tc.kasLatestAvailableRevision(t, testCtx)
		auth, err := tc.configClient.ConfigV1().Authentications().Get(testCtx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("cleanup failed for authentication '%s' while retrieving fresh object: %v", auth.Name, err)
		}

		auth.Spec = *origAuthSpec
		if _, err := tc.configClient.ConfigV1().Authentications().Update(testCtx, auth, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("cleanup failed for authentication '%s' while updating object: %v", auth.Name, err)
		}

		err = test.WaitForNewKASRollout(t, testCtx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
		require.NoError(t, err, "failed to wait for KAS rollout during cleanup")

		err = wait.PollUntilContextTimeout(testCtx, 10*time.Second, 5*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			return tc.validateOAuthResources(testCtx, false)
		})
		require.NoError(t, err, "failed to wait for OAuth resources to be present during cleanup")
	})

	// keycloak setup
	var idpName string
	var kcClient *test.KeycloakClient
	kcClient, idpName, cleanups = test.AddKeycloakIDP(t, tc.kubeConfig, true)
	t.Logf("keycloak Admin URL: %s", kcClient.AdminURL())

	// default-ingress-cert is copied to openshift-config and used as the CA for the IdP
	// see test/library/idpdeployment.go:332
	idpURL := kcClient.IssuerURL()
	caBundleName := idpName + "-ca"
	_, err = tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Get(testCtx, caBundleName, metav1.GetOptions{})
	require.NoError(t, err, "CA bundle configmap openshift-config/%s must exist", caBundleName)

	for _, tt := range []struct {
		name                        string
		authSpec                    configv1.AuthenticationSpec
		expectedUsernamePrefix      string
		expectOperatorDegraded      bool
		expectOIDCRolloutSuccessful bool
	}{
		{
			name: "invalid OIDC config degrades operator",
			authSpec: getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName+"_invalid", oidcGroupsClaim, oidcClientId, configv1.UsernameClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: "email",
				},
				PrefixPolicy: configv1.Prefix,
				Prefix: &configv1.UsernamePrefix{
					PrefixString: "oidc-test:",
				},
			}),
			expectedUsernamePrefix:      "oidc-test:",
			expectOperatorDegraded:      true,
			expectOIDCRolloutSuccessful: false,
		},
		{
			name: "valid OIDC rollout with username prefix",
			authSpec: getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName, oidcGroupsClaim, oidcClientId, configv1.UsernameClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: "email",
				},
				PrefixPolicy: configv1.Prefix,
				Prefix: &configv1.UsernamePrefix{
					PrefixString: "oidc-test:",
				},
			}),
			expectedUsernamePrefix:      "oidc-test:",
			expectOperatorDegraded:      false,
			expectOIDCRolloutSuccessful: true,
		},
		{
			name: "valid OIDC rollout with no username prefix",
			authSpec: getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName, oidcGroupsClaim, oidcClientId, configv1.UsernameClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: "email",
				},
				PrefixPolicy: configv1.NoPrefix,
			}),
			expectedUsernamePrefix:      "",
			expectOperatorDegraded:      false,
			expectOIDCRolloutSuccessful: true,
		},
		{
			name: "valid OIDC rollout with no-opinion on username prefix and claim sub",
			authSpec: getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName, oidcGroupsClaim, oidcClientId, configv1.UsernameClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: "sub",
				},
				PrefixPolicy: configv1.NoOpinion,
			}),
			expectedUsernamePrefix:      idpURL + "#",
			expectOperatorDegraded:      false,
			expectOIDCRolloutSuccessful: true,
		},
		{
			name: "valid OIDC rollout with no-opinion on username prefix and claim email",
			authSpec: getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName, oidcGroupsClaim, oidcClientId, configv1.UsernameClaimMapping{
				TokenClaimMapping: configv1.TokenClaimMapping{
					Claim: "email",
				},
				PrefixPolicy: configv1.NoOpinion,
			}),
			expectedUsernamePrefix:      "",
			expectOperatorDegraded:      false,
			expectOIDCRolloutSuccessful: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auth := tc.getAuth(t, testCtx)
			kasOriginalRevision := tc.kasLatestAvailableRevision(t, testCtx)

			auth.Spec = tt.authSpec
			auth, err := tc.configClient.ConfigV1().Authentications().Update(testCtx, auth, metav1.UpdateOptions{})
			require.NoError(t, err, "failed to update authentication/cluster")
			require.True(t, equality.Semantic.DeepEqual(tt.authSpec, auth.Spec))

			if tt.expectOperatorDegraded {
				err = test.WaitForClusterOperatorDegraded(t, tc.configClient.ConfigV1(), "authentication")
				require.NoError(t, err, "failed to wait for cluster operator to get degraded")
			} else {
				err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, tc.configClient.ConfigV1(), "authentication")
				require.NoError(t, err, "failed to wait for cluster operator to become available")
			}

			if tt.expectOIDCRolloutSuccessful {
				// wait for KAS rollout
				err = test.WaitForNewKASRollout(t, testCtx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOriginalRevision)
				require.NoError(t, err, "failed to wait for KAS rollout")

				kasRevision := tc.validateKASConfig(t, testCtx)
				tc.validateAuthConfigJSON(t, testCtx, kcClient.IssuerURL(), &tt.authSpec, tt.expectedUsernamePrefix, oidcGroupsClaim, oidcGroupsPrefix, kasRevision)

				// TODO enable this test once OAuth cleanup has been implemented
				// wait for OAuth resources to be cleaned up
				// err = wait.PollUntilContextTimeout(testCtx, 10*time.Second, 5*time.Minute, true, func(ctx context.Context) (done bool, err error) {
				// 	return tc.validateOAuthResources(testCtx, true)
				// })
				// require.NoError(t, err, "failed to wait for OAuth resources to be missing")

				// run auth tests
				tc.testOIDCAuthentication(t, testCtx, kcClient, tt.authSpec.OIDCProviders[0].ClaimMappings.Username.Claim, tt.expectedUsernamePrefix)
			}

		})
	}
}

func newTestClient(t *testing.T) (*testClient, error) {
	tc := &testClient{
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

	keyfunc := func(token *jwt.Token) (any, error) {
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

func (tc *testClient) getAuth(t *testing.T, ctx context.Context) *configv1.Authentication {
	auth, err := tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err, "failed to get authentication/cluster")
	require.NotNil(t, auth)

	return auth
}

func (tc *testClient) kasLatestAvailableRevision(t *testing.T, ctx context.Context) int32 {
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err, "failed to get kubeapiserver/cluster")
	return kas.Status.LatestAvailableRevision
}

func getAuthSpecForOIDCProvider(idpName, idpURL, caBundleName, groupsClaim string, oidcClientID configv1.TokenAudience, usernameMapping configv1.UsernameClaimMapping) configv1.AuthenticationSpec {
	auth := configv1.AuthenticationSpec{
		Type:                      configv1.AuthenticationTypeOIDC,
		WebhookTokenAuthenticator: nil,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: idpName,
				Issuer: configv1.TokenIssuer{
					URL:       idpURL,
					Audiences: []configv1.TokenAudience{oidcClientID},
					CertificateAuthority: configv1.ConfigMapNameReference{
						Name: caBundleName,
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: usernameMapping,
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: groupsClaim,
						},
					},
				},
			},
		},
	}

	return auth
}

func (tc *testClient) validateKASConfig(t *testing.T, ctx context.Context) int32 {
	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	var observedConfig map[string]any
	err = json.Unmarshal(kas.Spec.ObservedConfig.Raw, &observedConfig)
	require.NoError(t, err)

	apiServerArguments := observedConfig["apiServerArguments"].(map[string]any)

	require.Nil(t, apiServerArguments["authentication-token-webhook-config-file"])
	require.Nil(t, apiServerArguments["authentication-token-webhook-version"])
	require.Nil(t, observedConfig["authConfig"])

	authConfigArg := apiServerArguments["authentication-config"].([]any)
	require.NotEmpty(t, authConfigArg)
	require.Equal(t, authConfigArg[0].(string), "/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json")

	return kas.Status.LatestAvailableRevision
}

func (tc *testClient) validateAuthConfigJSON(t *testing.T, ctx context.Context, idpURL string, authSpec *configv1.AuthenticationSpec, usernamePrefix, groupsClaim, groupsPrefix string, kasRevision int32) {
	caBundleName := authSpec.OIDCProviders[0].Issuer.CertificateAuthority.Name
	certData := ""
	if len(caBundleName) > 0 {
		cm, err := tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Get(ctx, caBundleName, metav1.GetOptions{})
		require.NoError(t, err)
		certData = cm.Data["ca-bundle.crt"]
	}

	expectedAuthConfigJSON := fmt.Sprintf(`{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"%s","certificateAuthority":"%s","audiences":[%s],"audienceMatchPolicy":"MatchAny"},"claimMappings":{"username":{"claim":"%s","prefix":"%s"},"groups":{"claim":"%s","prefix":"%s"},"uid":{}}}]}`,
		idpURL,
		strings.ReplaceAll(certData, "\n", "\\n"),
		strings.Join([]string{fmt.Sprintf(`"%s"`, oidcClientId)}, ","),
		authSpec.OIDCProviders[0].ClaimMappings.Username.Claim,
		usernamePrefix,
		groupsClaim,
		groupsPrefix,
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
		require.NoError(t, err)
		require.Equal(t, expectedAuthConfigJSON, actualCM.Data["auth-config.json"], "unexpected auth-config.json contents in %s/%s", actualCM.Namespace, actualCM.Name)
	}
}

type namespacedObject struct {
	namespace string
	name      string
}

func (tc *testClient) validateOAuthResources(ctx context.Context, requireMissing bool) (bool, error) {
	dynamicClient, err := dynamic.NewForConfig(tc.kubeConfig)
	if err != nil {
		return false, fmt.Errorf("unexpected error while creating dynamic client: %v", err)
	}

	for _, obj := range []struct {
		gvr       string
		namespace string
		name      string
	}{
		{"deployments.v1.apps", "openshift-authentication", "oauth-openshift"},
		{"deployments.v1.apps", "openshift-oauth-apiserver", "apiserver"},
		{"configmaps.v1", "openshift-authentication", "v4-0-config-system-metadata"},
		{"configmaps.v1", "openshift-authentication", "v4-0-config-system-trusted-ca-bundle"},
		{"configmaps.v1", "openshift-authentication", "v4-0-config-system-service-ca"},
		{"configmaps.v1", "openshift-authentication", "v4-0-config-system-cliconfig"},
		{"secrets.v1", "openshift-authentication", "v4-0-config-system-ocp-branding-template"},
		{"secrets.v1", "openshift-authentication", "v4-0-config-system-session"},
		{"services.v1", "openshift-authentication", "oauth-openshift"},
		{"apiservices.v1.apiregistration.k8s.io", "", "v1.oauth.openshift.io"},
		{"apiservices.v1.apiregistration.k8s.io", "", "v1.user.openshift.io"},
		{"oauthclients.v1.oauth.openshift.io", "", "openshift-browser-client"},
		{"oauthclients.v1.oauth.openshift.io", "", "openshift-challenging-client"},
		{"oauthclients.v1.oauth.openshift.io", "", "openshift-cli-client"},
	} {
		gvr, gr := schema.ParseResourceArg(obj.gvr)
		if gvr != nil {
			fmt.Printf("%s GVR: Group=%s Version=%s Resource=%s\n", obj.gvr, gvr.Group, gvr.Version, gvr.Resource)
		} else {
			fmt.Printf("no GVR; GR: Group=%s Resource=%s\n", gr.Group, gr.Resource)
		}
		_, err := dynamicClient.Resource(*gvr).Namespace(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return false, fmt.Errorf("unexpected error while getting resource %s/%s: %v", obj.namespace, obj.name, err)
		} else if requireMissing != errors.IsNotFound(err) {
			return false, fmt.Errorf("resource %s/%s wanted missing: %v; got: %v", obj.namespace, obj.name, requireMissing, !errors.IsNotFound((err)))
		}
	}

	// routes
	for _, obj := range []namespacedObject{
		{"openshift-authentication", "oauth-openshift"},
	} {
		_, err := tc.routeClient.RouteV1().Routes(obj.namespace).Get(ctx, obj.name, metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return false, fmt.Errorf("unexpected error while getting route %s/%s: %v", obj.namespace, obj.name, err)
		} else if requireMissing != errors.IsNotFound(err) {
			return false, fmt.Errorf("route %s/%s wanted missing: %v; got: %v", obj.namespace, obj.name, requireMissing, !errors.IsNotFound((err)))
		}

		// ingress status
		ingress, err := tc.configClient.ConfigV1().Ingresses().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		found := false
		for _, route := range ingress.Status.ComponentRoutes {
			if route.Name == obj.name && route.Namespace == obj.namespace {
				found = true
				break
			}
		}

		if requireMissing != !found {
			return false, fmt.Errorf("route %s wanted missing: %v; got: %v", obj, requireMissing, !found)
		}
	}

	return true, nil
}

func (tc *testClient) testOIDCAuthentication(t *testing.T, ctx context.Context, kcClient *test.KeycloakClient, usernameClaim, usernamePrefix string) {
	// re-authenticate to ensure we always have a fresh token
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword(oidcClientId, "", "admin", "password")
		return err == nil, err
	})
	require.NoError(t, err)

	group := names.SimpleNameGenerator.GenerateName("e2e-keycloak-group-")
	err = kcClient.CreateGroup(group)
	require.NoError(t, err)

	user := names.SimpleNameGenerator.GenerateName("e2e-keycloak-user-")
	email := fmt.Sprintf("%s@test.dev", user)
	password := "password"
	firstName := "Homer"
	lastName := "Simpson"
	err = kcClient.CreateUser(
		user,
		email,
		password,
		[]string{group},
		map[string]string{
			"firstName": firstName,
			"lastName":  lastName,
		},
	)
	require.NoError(t, err)

	// use a keycloak client for the user created above to fetch its tokens
	transport, err := rest.TransportFor(tc.kubeConfig)
	require.NoError(t, err)
	userClient := test.KeycloakClientFor(t, transport, kcClient.IssuerURL(), "master")
	err = userClient.AuthenticatePassword(oidcClientId, "", user, password)
	require.NoError(t, err)
	accessTokenStr, idTokenStr := userClient.Tokens()
	require.NotEmpty(t, accessTokenStr, "access token must not be empty")
	require.NotEmpty(t, idTokenStr, "id token must not be empty")

	// validate the contents of the OIDC tokens
	accessToken, idToken, err := parseOIDCTokens(userClient.IssuerURL(), accessTokenStr, idTokenStr)
	require.NoError(t, err)
	require.NotNil(t, accessToken)
	require.NotNil(t, idToken)

	actualAccessTokenClaims := accessToken.Claims.(*expectedClaims)
	require.True(t, accessToken.Valid)
	require.Equal(t, userClient.IssuerURL(), actualAccessTokenClaims.Issuer)
	require.Equal(t, user, actualAccessTokenClaims.PreferredUsername)
	require.Equal(t, email, actualAccessTokenClaims.Email)
	require.Equal(t, "Bearer", actualAccessTokenClaims.Type)
	require.Equal(t, firstName, actualAccessTokenClaims.GivenName)
	require.Equal(t, lastName, actualAccessTokenClaims.FamilyName)
	require.Equal(t, fmt.Sprintf("%s %s", firstName, lastName), actualAccessTokenClaims.Name)
	require.NotEmpty(t, actualAccessTokenClaims.Subject)

	actualIDTokenClaims := idToken.Claims.(*expectedClaims)
	require.True(t, idToken.Valid)
	require.Equal(t, userClient.IssuerURL(), actualIDTokenClaims.Issuer)
	require.Equal(t, user, actualIDTokenClaims.PreferredUsername)
	require.Equal(t, email, actualIDTokenClaims.Email)
	require.Equal(t, "ID", actualIDTokenClaims.Type)
	require.Equal(t, jwt.ClaimStrings{oidcClientId}, actualIDTokenClaims.Audience)
	require.Equal(t, firstName, actualIDTokenClaims.GivenName)
	require.Equal(t, lastName, actualIDTokenClaims.FamilyName)
	require.Equal(t, fmt.Sprintf("%s %s", firstName, lastName), actualIDTokenClaims.Name)
	require.NotEmpty(t, actualIDTokenClaims.Subject)

	// test authentication via the kube-apiserver
	// create a new kube client that uses the OIDC id_token as a bearer token
	kubeConfig := rest.AnonymousClientConfig(tc.kubeConfig)
	kubeConfig.BearerToken = idTokenStr
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	// test authentication with the OIDC token using a self subject review
	expectedUsername := ""
	switch usernameClaim {
	case "email":
		expectedUsername = usernamePrefix + email
	case "sub":
		expectedUsername = usernamePrefix + actualIDTokenClaims.Subject
	default:
		t.Fatalf("unexpected username claim: %s", usernameClaim)
	}

	ssr, err := kubeClient.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NotNil(t, ssr)
	require.Contains(t, ssr.Status.UserInfo.Groups, "system:authenticated")
	require.Equal(t, expectedUsername, ssr.Status.UserInfo.Username)
}
