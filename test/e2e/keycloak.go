package e2e

import (
	"bytes"
	"context"
	"math/rand"
	"net/http"
	"strconv"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest/challengehandlers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[OIDC][Serial] TestKeycloakAsOIDCPasswordGrantCheckAndGroupSync", func() {
		testKeycloakAsOIDCPasswordGrantCheckAndGroupSync(g.GinkgoTB())
	})
})

func testKeycloakAsOIDCPasswordGrantCheckAndGroupSync(t testing.TB) {
	testContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	clients := test.NewTestClients(t)
	kubeConfig := test.NewClientConfigForTest(t)

	_, idpName, cleanups := test.AddKeycloakIDP(t, kubeConfig, false)
	defer test.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	// ==============================================================================
	// Test that we don't consider the provider as a challenger if ROPC is not set up
	// ==============================================================================
	// Wait for the IDP to appear in the OAuth server config
	// In parallel execution, initial IDP creation and propagation can take longer
	var kcIDPConfig *osinv1.IdentityProvider
	var err error
	err = wait.PollImmediate(2*time.Second, 5*time.Minute, func() (bool, error) {
		config, err := test.GrabOAuthServerConfig(clients.KubeClient.CoreV1())
		if err != nil {
			t.Logf("failed to get OAuth server config: %v", err)
			return false, nil
		}

		kcIDPConfig = test.GetIDPByName(config, idpName)
		if kcIDPConfig == nil {
			t.Logf("IDP %q not found in OAuth server config yet", idpName)
			return false, nil
		}

		return true, nil
	})
	require.NoError(t, err, "IDP %q did not appear in OAuth server config", idpName)

	require.Equal(t, false, kcIDPConfig.UseAsChallenger, "keycloak is configured as challenger but it should not be")

	// =======================================================================
	// Test that we do consider the provider as a challenger if ROPC is set up
	// =======================================================================
	// Wait for the IDP to appear in the OAuth config with proper OpenID configuration
	// In parallel execution, operator may take longer to create OAuth cluster configuration
	var configIDP configv1.IdentityProvider
	err = wait.PollImmediate(2*time.Second, 5*time.Minute, func() (bool, error) {
		oauthConfig, err := clients.ConfigClient.ConfigV1().OAuths().Get(testContext, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to get OAuth config: %v", err)
			return false, nil
		}

		for _, idp := range oauthConfig.Spec.IdentityProviders {
			if idp.Name == idpName {
				if idp.OpenID != nil && idp.OpenID.Issuer != "" && idp.OpenID.ClientSecret.Name != "" {
					configIDP = idp
					return true, nil
				}
				t.Logf("found IDP %q but OpenID config is incomplete", idpName)
				return false, nil
			}
		}
		t.Logf("IDP %q not found in OAuth config yet", idpName)
		return false, nil
	})
	require.NoError(t, err, "IDP %q did not appear in OAuth config with valid OpenID configuration", idpName)

	// Get a keycloak client for the external KC URL
	transport, err := rest.TransportFor(kubeConfig)
	require.NoError(t, err)

	kcClient := test.KeycloakClientFor(t, transport, configIDP.OpenID.Issuer, "master")
	err = kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
	require.NoError(t, err)

	client, err := kcClient.GetClientByClientID(configIDP.OpenID.ClientID)
	require.NoError(t, err)

	err = kcClient.UpdateClientDirectAccessGrantsEnabled(client["id"].(string), true)
	require.NoError(t, err)

	// ===================================================================
	// VERIFY KEYCLOAK IS FULLY READY BEFORE BUMPING SECRET
	// ===================================================================
	// In parallel execution with resource constraints, Keycloak may be slow to respond
	// to token requests even after initial authentication succeeds. The operator will
	// attempt to validate the password grant flow when we bump the secret, so we must
	// ensure Keycloak can actually handle those requests before proceeding.
	t.Logf("verifying Keycloak is ready to handle password grant requests before triggering operator validation")

	err = wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		// Re-authenticate to verify admin API is still responsive
		err := kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
		if err != nil {
			t.Logf("Keycloak authentication not ready: %v", err)
			return false, nil
		}

		// Verify the token endpoint is responsive by testing an actual password grant request
		// This simulates what the operator will do when validating the IDP configuration
		// The health endpoint is at the root, but we need to test the actual token endpoint
		// that the operator uses for password grant validation
		tokenURL := configIDP.OpenID.Issuer + "/protocol/openid-connect/token"

		// Prepare a test password grant request (with invalid credentials)
		// We're just checking if the endpoint is responsive, not if auth succeeds
		testData := "grant_type=password&client_id=" + configIDP.OpenID.ClientID + "&username=test&password=test&scope=openid"
		req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(testData))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		httpClient := &http.Client{Transport: transport}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Logf("Keycloak token endpoint not reachable: %v", err)
			return false, nil
		}
		defer resp.Body.Close()

		// Check for 5xx errors that would cause operator validation to fail
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			t.Logf("Keycloak token endpoint returning server error: HTTP %d", resp.StatusCode)
			return false, nil
		}

		// Any response other than 5xx means Keycloak is responsive
		// (4xx means bad credentials which is expected, 2xx means it worked)
		t.Logf("Keycloak is ready: token endpoint responsive (HTTP %d)", resp.StatusCode)
		return true, nil
	})
	require.NoError(t, err, "Keycloak did not become fully ready before secret update")

	// bump the configured secret since the operator caches the password grant check
	// based on it
	configSecretName := configIDP.OpenID.ClientSecret.Name
	configSecret, err := clients.KubeClient.CoreV1().Secrets("openshift-config").Get(testContext, configSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	if configSecret.Annotations == nil {
		configSecret.Annotations = map[string]string{}
	}
	configSecret.Annotations["bumped"] = strconv.FormatUint(rand.Uint64(), 10)
	_, err = clients.KubeClient.CoreV1().Secrets("openshift-config").Update(testContext, configSecret, metav1.UpdateOptions{})
	require.NoError(t, err)

	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	require.NoError(t, err)

	// Wait for OAuth server pods to be updated with new configuration
	waitOAuthServerReplicasReady(t, clients.KubeClient)

	// Wait for the OAuth server config to reflect UseAsChallenger=true after ROPC enablement
	// In parallel execution, operator reconciliation and config propagation can take longer
	err = wait.PollImmediate(2*time.Second, 5*time.Minute, func() (bool, error) {
		config, err := test.GrabOAuthServerConfig(clients.KubeClient.CoreV1())
		if err != nil {
			t.Logf("failed to get OAuth server config: %v", err)
			return false, nil
		}

		kcIDPConfig = test.GetIDPByName(config, idpName)
		if kcIDPConfig == nil {
			t.Logf("IDP %q not found in OAuth server config yet", idpName)
			return false, nil
		}

		if !kcIDPConfig.UseAsChallenger {
			t.Logf("IDP %q found but UseAsChallenger is still false, waiting for update", idpName)
			return false, nil
		}

		return true, nil
	})
	require.NoError(t, err, "IDP %q did not get UseAsChallenger=true in OAuth server config", idpName)

	require.Equal(t, true, kcIDPConfig.UseAsChallenger, "keycloak is not configured as challenger but it should be")

	// ================================
	// Test groups are synced from OIDC
	// ================================
	groups := []string{"group1", "group2", "group3"}
	require.NoError(t, kcClient.CreateGroup("group1"))
	require.NoError(t, kcClient.CreateGroup("group2"))
	require.NoError(t, kcClient.CreateGroup("group3"))

	username := "douglasnoeladams"
	require.NoError(t, kcClient.CreateUser(
		username, "", "password42",
		groups,
		nil,
	))

	// we need to repeat challenger creation as they remember handling the challenge and won't do that twice
	createChallengeHandler := func(username, password string) *challengehandlers.BasicChallengeHandler {
		return challengehandlers.NewBasicChallengeHandler(
			kubeConfig.Host, "",
			nil, nil, nil,
			username, password,
		)
	}

	_, err = tokenrequest.RequestTokenWithChallengeHandlers(kubeConfig, createChallengeHandler(username, "password42"))
	require.NoError(t, err)

	defer func() {
		for _, g := range groups {
			if err := clients.UserClient.Groups().Delete(context.Background(), g, metav1.DeleteOptions{}); err != nil {
				t.Logf("failed to remove group %q: %v", g, err)
			}
		}

		if err := clients.UserClient.Users().Delete(context.Background(), username, metav1.DeleteOptions{}); err != nil {
			t.Logf("failed to remove user %q: %v", username, err)
		}
	}()

	for _, g := range groups {
		group, err := clients.UserClient.Groups().Get(context.Background(), g, metav1.GetOptions{})
		require.NoError(t, err)
		require.Contains(t, group.Users, username)
	}

	// ==================================================================================
	// Test groups get removed if the user is the last and they were synced from the OIDC
	// ==================================================================================
	users, err := kcClient.ListUsers()
	require.NoError(t, err)
	var userId string
	for _, u := range users {
		if u["username"] == username {
			userId = u["id"].(string)
			break
		}
	}
	require.NotEmpty(t, userId, "failed to find user id for %q", username)

	userGroups, err := kcClient.ListUserGroups(userId)
	require.NoError(t, err)

	userGroupsIDMap := make(map[string]string, len(userGroups))
	for _, g := range userGroups {
		userGroupsIDMap[g["name"].(string)] = g["id"].(string)

	}
	require.NoError(t, kcClient.DeleteUserFromGroups(userId, userGroupsIDMap["group2"], userGroupsIDMap["group3"]))
	removedGroups := sets.New[string]("group2", "group3")

	_, err = tokenrequest.RequestTokenWithChallengeHandlers(kubeConfig, createChallengeHandler(username, "password42"))
	require.NoError(t, err)

	groupList, err := clients.UserClient.Groups().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	for _, g := range groupList.Items {
		require.False(t, removedGroups.Has(g.Name), "group %q is still present but should have been removed\n%v", g.Name, g)
	}
}
