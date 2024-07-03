package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	v1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorversionedclient "github.com/openshift/client-go/operator/clientset/versioned"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
)

const (
	externalOIDCFeatureGate = "ExternalOIDC"

	oidcClientId      = "admin-cli"
	oidcAudience      = "openshift-aud"
	oidcGroupsClaim   = "groups"
	oidcUsernameClaim = "email"
)

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
	kubeConfig := test.NewClientConfigForTest(t)
	configClient, err := configclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oidcEnabled, err := featureGateEnabled(testCtx, configClient, externalOIDCFeatureGate)
	require.NoError(t, err)
	if !oidcEnabled {
		t.Skipf("%s feature gate disabled", externalOIDCFeatureGate)
	}

	var kcClient *test.KeycloakClient
	if keycloakURL := os.Getenv("E2E_KEYCLOAK_URL"); len(keycloakURL) > 0 {
		t.Logf("will use existing keycloak deployment at URL: %s", keycloakURL)
		kcClient = setupKeycloakClient(t, testCtx, kubeConfig, keycloakURL)

	} else {
		t.Logf("no existing keycloak deployment found; will create new")
		var cleanups []func()
		kcClient, cleanups = setupExternalOIDCWithKeycloak(t, testCtx, kubeConfig, configClient)
		defer test.IDPCleanupWrapper(func() {
			for _, c := range cleanups {
				c()
			}
		})()
		t.Logf("keycloak Admin URL: %s", kcClient.AdminURL())
	}

	// ====================================
	// Do some basic Keycloak sanity checks
	// ====================================

	kcAdminClient, err := kcClient.GetClientByClientID(oidcClientId)
	require.NoError(t, err)
	require.NotEmpty(t, kcAdminClient)

	group := names.SimpleNameGenerator.GenerateName("e2e-keycloak-group-")
	err = kcClient.CreateGroup(group)
	require.NoError(t, err)

	user := names.SimpleNameGenerator.GenerateName("e2e-keycloak-user-")
	password := "password"
	err = kcClient.CreateUser(user, password, []string{group})
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
	kasURL := fmt.Sprintf("%s/api/v1/namespaces", kubeConfig.Host)
	req, err := http.NewRequest(http.MethodGet, kasURL, nil)
	require.NoError(t, err)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authResponse.AccessToken))
	d, _ := httputil.DumpRequest(req, false)
	t.Log(string(d))
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func setupKeycloakClient(t *testing.T, ctx context.Context, kubeConfig *rest.Config, keycloakURL string) *test.KeycloakClient {
	transport, err := rest.TransportFor(kubeConfig)
	require.NoError(t, err)

	kcClient := test.KeycloakClientFor(t, transport, keycloakURL, "master")
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kcClient.AuthenticatePassword(oidcClientId, "", "admin", "password")
		if err != nil {
			t.Logf("failed to authenticate to Keycloak: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	return kcClient
}

func setupExternalOIDCWithKeycloak(t *testing.T, ctx context.Context, kubeConfig *rest.Config, configClient *configclient.Clientset) (kcClient *test.KeycloakClient, cleanups []func()) {
	kcClient, idpName, c := test.AddKeycloakIDP(t, kubeConfig, true)
	cleanups = append(cleanups, c...)

	// patch proxy/cluster to access the default-ingress-cert that now exists in openshift-config
	c, err := updateProxyForIngressCert(t, ctx, configClient)
	cleanups = append(cleanups, c...)
	require.NoError(t, err)

	// setup kube-apiserver to access the external OIDC directly by modifying its args via UnsupportedConfigOverrides
	c, err = updateKASArgsForOIDC(t, ctx, kubeConfig, kcClient.IssuerURL())
	cleanups = append(cleanups, c...)
	require.NoError(t, err)

	t.Skip("proxy & kas patched")

	// update the authentication CR with the external OIDC configuration
	c, err = updateAuthForOIDC(t, ctx, configClient, kcClient.IssuerURL(), idpName)
	cleanups = append(cleanups, c...)
	require.NoError(t, err)
	t.Skip("auth patched")

	return
}

func featureGateEnabled(ctx context.Context, configClient *configclient.Clientset, featureGateName string) (bool, error) {
	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	for _, fgStatus := range featureGates.Status.FeatureGates {
		for _, fgEnabled := range fgStatus.Enabled {
			if fgEnabled.Name == configv1.FeatureGateName(featureGateName) {
				return true, nil
			}
		}
	}

	return false, nil
}

func updateProxyForIngressCert(t *testing.T, ctx context.Context, configClient *configclient.Clientset) (cleanups []func(), err error) {
	proxy, err := configClient.ConfigV1().Proxies().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return
	}

	origTrustedCAName := proxy.Spec.TrustedCA.Name
	proxy.Spec.TrustedCA.Name = "default-ingress-cert"
	proxy, err = configClient.ConfigV1().Proxies().Update(ctx, proxy, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	cleanups = append(cleanups, func() {
		proxy.Spec.TrustedCA.Name = origTrustedCAName
		proxy, err = configClient.ConfigV1().Proxies().Update(ctx, proxy, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("cleanup failed for proxy '%s': %v", proxy.Name, err)
		}
	})

	return
}

func updateKASArgsForOIDC(t *testing.T, ctx context.Context, kubeConfig *rest.Config, idpURL string) (cleanups []func(), err error) {
	operatorConfigClient, err := operatorversionedclient.NewForConfig(kubeConfig)
	if err != nil {
		return
	}

	unsupportedConfigOverrides := fmt.Sprintf(`{
		"apiServerArguments": {
			"oidc-ca-file": ["/etc/kubernetes/static-pod-certs/configmaps/trusted-ca-bundle/ca-bundle.crt"],
			"oidc-client-id": ["%s"],
			"oidc-issuer-url": ["%s"],
			"oidc-groups-claim": ["%s"],
			"oidc-username-claim": ["%s"],
			"oidc-username-prefix":["-"]
		}
	}`, oidcClientId, idpURL, oidcGroupsClaim, oidcUsernameClaim)

	kas, err := operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return
	}

	origUnsupportedConfigOverides := kas.Spec.UnsupportedConfigOverrides
	kas.Spec.UnsupportedConfigOverrides = runtime.RawExtension{Raw: []byte(unsupportedConfigOverrides)}
	cleanups, err = kasUpdateAndWaitForRollout(t, ctx, kas, operatorConfigClient)
	if err != nil {
		return
	}

	cleanups = append(cleanups, func() {
		kas, err := operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("cleanup failed for kube-apiserver '%s', while getting fresh object: %v", kas.Name, err)
			return
		}

		kas.Spec.UnsupportedConfigOverrides = origUnsupportedConfigOverides
		cleanups, err = kasUpdateAndWaitForRollout(t, ctx, kas, operatorConfigClient)
		if err != nil {
			t.Logf("cleanup failed for kube-apiserver '%s': %v", kas.Name, err)
			return
		}
	})

	return
}

// TODO: move waits to test/library/waits.go
func kasUpdateAndWaitForRollout(t *testing.T, ctx context.Context, kas *v1.KubeAPIServer, operatorConfigClient *operatorversionedclient.Clientset) (cleanups []func(), err error) {
	origRevision := kas.Status.LatestAvailableRevision
	kas, err = operatorConfigClient.OperatorV1().KubeAPIServers().Update(ctx, kas, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, 15*time.Minute, true, func(ctx context.Context) (bool, error) {
		kas, err := operatorConfigClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if errors.IsNotFound(err) || retry.IsHTTPClientError(err) {
			t.Logf("kube-apiserver 'cluster' error (will retry): %v", err)
			return false, nil

		} else if err != nil {
			return false, err
		}

		for _, nodeStatus := range kas.Status.NodeStatuses {
			if kas.Status.LatestAvailableRevision == origRevision || nodeStatus.CurrentRevision != kas.Status.LatestAvailableRevision {
				fmt.Printf("%s: %d (want %d)\n", nodeStatus.NodeName, nodeStatus.CurrentRevision, kas.Status.LatestAvailableRevision)
				return false, nil
			}
		}

		return true, nil
	})
	if err != nil {
		return
	}

	return
}

func updateAuthForOIDC(t *testing.T, ctx context.Context, configClient *configclient.Clientset, idpURL, idpName string) (cleanups []func(), err error) {
	auth, err := configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
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

	_, err = configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	cleanups = append(cleanups, func() {
		auth.Spec = *origSpec
		_, err = configClient.ConfigV1().Authentications().Update(ctx, auth, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("cleanup failed for authentication '%s': %v", auth.Name, err)
		}
	})

	// wait for the openshift-console/console oidc client in .status.oidcClients to reach the Available condition
	waitOIDCClientAvailableFunc := func(event watch.Event) (bool, error) {
		auth := event.Object.(*configv1.Authentication)
		for _, oidcClient := range auth.Status.OIDCClients {
			if oidcClient.ComponentName != "console" || oidcClient.ComponentNamespace != "openshift-console" {
				continue
			}

			// poll while Available != True OR Progressing == True OR Degraded == True
			for _, condition := range oidcClient.Conditions {
				if condition.Type == "Available" && condition.Status != metav1.ConditionTrue {
					return false, nil
				}
				if condition.Type == "Progressing" && condition.Status == metav1.ConditionTrue {
					return false, nil
				}
				if condition.Type == "Degraded" && condition.Status == metav1.ConditionTrue {
					return false, nil
				}
			}

			return true, nil
		}

		return false, nil
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Minute)
	cleanups = append(cleanups, cancel)

	_, err = watchtools.UntilWithSync(ctxWithTimeout,
		cache.NewListWatchFromClient(configClient.ConfigV1().RESTClient(), "authentications", "", fields.OneTermEqualSelector("metadata.name", "cluster")),
		&configv1.Authentication{},
		nil,
		waitOIDCClientAvailableFunc,
	)

	return
}
