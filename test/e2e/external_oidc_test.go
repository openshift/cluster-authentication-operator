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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	oidcClientId      = "admin-cli"
	oidcAudience      = "openshift-aud"
	oidcGroupsClaim   = "groups"
	oidcUsernameClaim = "email"

	kasNamespace = "openshift-kube-apiserver"

	// set if a specific CA bundle is needed for the OIDC provider
	oidcCABundleConfigMap          = ""
	oidcCABundleConfigMapNamespace = ""
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

	// update the authentication CR with the external OIDC configuration
	authConfig, c, err := tc.updateAuthForOIDC(ctx, kcClient.IssuerURL(), idpName)
	cleanups = append(cleanups, c...)
	require.NoError(tc.t, err)
	require.NotNil(tc.t, authConfig)
	require.NotEmpty(tc.t, authConfig.Spec.OIDCProviders)

	// patch proxy/cluster to access the default-ingress-cert that now exists in openshift-config
	c, err = tc.updateProxyForIngressCert(ctx)
	cleanups = append(cleanups, c...)
	require.NoError(tc.t, err)

	// sync service-ca signing certificate to the KAS nodes as a static resource so that it can be used with --oidc-ca-file
	c, err = tc.syncServingCA(ctx)
	cleanups = append(cleanups, c...)
	require.NoError(tc.t, err)

	// setup kube-apiserver to access the external OIDC directly by modifying its args via UnsupportedConfigOverrides
	kasOrigRev, c, err := tc.updateKASArgsForOIDC(ctx, kcClient.IssuerURL())
	cleanups = append(cleanups, c...)
	require.NoError(tc.t, err)

	// wait for serving CA and KAS args overrides to get rolled out
	tc.t.Log("will wait for KAS rollout")
	err = test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), kasOrigRev)
	require.NoError(tc.t, err)

	return
}

func (tc *testClient) updateProxyForIngressCert(ctx context.Context) (cleanups []func(), err error) {
	tc.t.Log("will copy default-ingress-cert and patch proxy")

	defaultIngressCert, err := tc.kubeClient.CoreV1().ConfigMaps("openshift-config-managed").Get(ctx, "default-ingress-cert", metav1.GetOptions{})
	if err != nil {
		return
	}

	cmCopy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultIngressCert.Name,
			Namespace: "openshift-config",
		},
		Data: defaultIngressCert.Data,
	}

	_, err = tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Create(ctx, cmCopy, metav1.CreateOptions{})
	cleanups = append(cleanups, func() {
		err := tc.kubeClient.CoreV1().ConfigMaps("openshift-config").Delete(ctx, cmCopy.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			tc.t.Fatalf("cleanup failed for configmap '%s/%s': %v", cmCopy.Namespace, cmCopy.Name, err)
		}
	})
	if err != nil {
		return
	}

	proxy, err := tc.configClient.ConfigV1().Proxies().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return
	}

	origTrustedCAName := proxy.Spec.TrustedCA.Name
	proxy.Spec.TrustedCA.Name = "default-ingress-cert"
	proxy, err = tc.configClient.ConfigV1().Proxies().Update(ctx, proxy, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		proxy.Spec.TrustedCA.Name = origTrustedCAName
		proxy, err = tc.configClient.ConfigV1().Proxies().Update(ctx, proxy, metav1.UpdateOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for proxy '%s': %v", proxy.Name, err)
		}
	})
	if err != nil {
		return
	}

	return
}

func (tc *testClient) syncServingCA(ctx context.Context) (cleanups []func(), err error) {
	if len(oidcCABundleConfigMap) == 0 || len(oidcCABundleConfigMapNamespace) == 0 {
		tc.t.Log("no oidc CA defined; will use system CA")
		return nil, nil
	}

	tc.t.Log("will sync OIDC ca-bundle to KAS static pod resources")

	signingKey, err := tc.kubeClient.CoreV1().ConfigMaps(oidcCABundleConfigMapNamespace).Get(ctx, oidcCABundleConfigMap, metav1.GetOptions{})
	if err != nil {
		return
	}

	// This functionality requires defining "oidc-serving-ca" as a RevisionConfigMap at the KAS-o
	// See example PR: https://github.com/openshift/cluster-kube-apiserver-operator/pull/1720
	oidcServingCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-serving-ca",
			Namespace: kasNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": string(signingKey.Data["tls.crt"]),
		},
	}

	_, err = tc.kubeClient.CoreV1().ConfigMaps(kasNamespace).Create(ctx, oidcServingCA, metav1.CreateOptions{})
	cleanups = append(cleanups, func() {
		err := tc.kubeClient.CoreV1().ConfigMaps(kasNamespace).Delete(ctx, oidcServingCA.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			tc.t.Fatalf("cleanup failed for secret '%s/%s': %v", oidcServingCA.Namespace, oidcServingCA.Name, err)
		}
	})
	if err != nil {
		return
	}

	return
}

func (tc *testClient) updateKASArgsForOIDC(ctx context.Context, idpURL string) (origRevision int32, cleanups []func(), err error) {
	tc.t.Log("will update KAS args for OIDC")

	oidcCAFile := "/etc/kubernetes/static-pod-certs/configmaps/trusted-ca-bundle/ca-bundle.crt"
	if len(oidcCABundleConfigMap) > 0 {
		oidcCAFile = "/etc/kubernetes/static-pod-resources/configmaps/oidc-serving-ca/ca-bundle.crt"
	}

	unsupportedConfigOverrides := fmt.Sprintf(`{
		"apiServerArguments": {
			"oidc-ca-file": ["%s"],
			"oidc-client-id": ["%s"],
			"oidc-issuer-url": ["%s"],
			"oidc-groups-claim": ["%s"],
			"oidc-username-claim": ["%s"],
			"oidc-username-prefix":["-"]
		}
	}`, oidcCAFile, oidcClientId, idpURL, oidcGroupsClaim, oidcUsernameClaim)

	kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return
	}

	origRevision = kas.Status.LatestAvailableRevision
	origUnsupportedConfigOverides := kas.Spec.UnsupportedConfigOverrides
	kas.Spec.UnsupportedConfigOverrides = runtime.RawExtension{Raw: []byte(unsupportedConfigOverrides)}

	kas, err = tc.operatorConfigClient.OperatorV1().KubeAPIServers().Update(ctx, kas, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		kas, err := tc.operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for kube-apiserver '%s', while getting fresh object: %v", kas.Name, err)
		}

		origRevision := kas.Status.LatestAvailableRevision
		kas.Spec.UnsupportedConfigOverrides = origUnsupportedConfigOverides
		kas, err = tc.operatorConfigClient.OperatorV1().KubeAPIServers().Update(ctx, kas, metav1.UpdateOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for kube-apiserver '%s': %v", kas.Name, err)
		}

		err = test.WaitForNewKASRollout(tc.t, ctx, tc.operatorConfigClient.OperatorV1().KubeAPIServers(), origRevision)
		if err != nil {
			tc.t.Fatalf("cleanup failed for kube-apiserver '%s': %v", kas.Name, err)
		}
	})
	if err != nil {
		return
	}

	return
}

func (tc *testClient) updateAuthForOIDC(ctx context.Context, idpURL, idpName string) (auth *configv1.Authentication, cleanups []func(), err error) {
	tc.t.Log("will update auth CR for OIDC")

	auth, err = tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return
	}

	origSpec := auth.Spec.DeepCopy()
	auth.Spec.Type = configv1.AuthenticationTypeOIDC
	auth.Spec.WebhookTokenAuthenticator = nil
	auth.Spec.OIDCProviders = []configv1.OIDCProvider{
		{
			Name: idpName,
			Issuer: configv1.TokenIssuer{
				URL:       idpURL,
				Audiences: []configv1.TokenAudience{oidcAudience},
				CertificateAuthority: configv1.ConfigMapNameReference{
					Name: oidcCABundleConfigMap,
				},
			},
			ClaimMappings: configv1.TokenClaimMappings{
				Groups: configv1.PrefixedClaimMapping{
					TokenClaimMapping: configv1.TokenClaimMapping{
						Claim: oidcGroupsClaim,
					},
				},
				Username: configv1.UsernameClaimMapping{
					TokenClaimMapping: configv1.TokenClaimMapping{
						Claim: oidcUsernameClaim,
					},
				},
			},
			OIDCClients: []configv1.OIDCClientConfig{
				{
					ClientID:           "console",
					ClientSecret:       configv1.SecretNameReference{Name: "console-secret"},
					ComponentName:      "console",
					ComponentNamespace: "openshift-console",
				},
			},
		},
	}

	_, err = tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	cleanups = append(cleanups, func() {
		auth, err := tc.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while retrieving fresh object: %v", auth.Name, err)
		}

		auth.Spec = *origSpec
		_, err = tc.configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
		if err != nil {
			tc.t.Fatalf("cleanup failed for authentication '%s' while updating object: %v", auth.Name, err)
		}
	})
	if err != nil {
		return
	}

	return
}
