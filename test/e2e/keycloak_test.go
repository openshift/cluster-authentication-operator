package e2e

import (
	"context"
	"math/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest/challengehandlers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestKeycloakAsOIDCPasswordGrantCheckAndGroupSync(t *testing.T) {
	testContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeConfig := test.NewClientConfigForTest(t)

	kubeClients, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	configClient, err := configv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	userClient, err := userv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	_, idpName, cleanups := test.AddKeycloakIDP(t, kubeConfig, false)
	defer test.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	// ==============================================================================
	// Test that we don't consider the provider as a challenger if ROPC is not set up
	// ==============================================================================
	config, err := test.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	kcIDPConfig := test.GetIDPByName(config, idpName)
	require.NotNil(t, kcIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

	require.Equal(t, false, kcIDPConfig.UseAsChallenger, "keycloak is configured as challenger but it should not be")

	oauthConfig, err := configClient.OAuths().Get(testContext, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	// =======================================================================
	// Test that we do consider the provider as a challenger if ROPC is set up
	// =======================================================================
	var configIDP configv1.IdentityProvider
	for _, idp := range oauthConfig.Spec.IdentityProviders {
		if idp.Name == idpName {
			configIDP = idp
			break
		}
	}

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

	// bump the configured secret since the operator caches the password grant check
	// based on it
	configSecretName := configIDP.OpenID.ClientSecret.Name
	configSecret, err := kubeClients.CoreV1().Secrets("openshift-config").Get(testContext, configSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	if configSecret.Annotations == nil {
		configSecret.Annotations = map[string]string{}
	}
	configSecret.Annotations["bumped"] = strconv.FormatUint(rand.Uint64(), 10)
	_, err = kubeClients.CoreV1().Secrets("openshift-config").Update(testContext, configSecret, metav1.UpdateOptions{})
	require.NoError(t, err)

	err = test.WaitForOperatorToPickUpChanges(t, configClient, "authentication")
	require.NoError(t, err)

	config, err = test.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	kcIDPConfig = test.GetIDPByName(config, idpName)
	require.NotNil(t, kcIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

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
			if err := userClient.Groups().Delete(context.Background(), g, metav1.DeleteOptions{}); err != nil {
				t.Logf("failed to remove group %q: %v", g, err)
			}
		}

		if err := userClient.Users().Delete(context.Background(), username, metav1.DeleteOptions{}); err != nil {
			t.Logf("failed to remove user %q: %v", username, err)
		}
	}()

	for _, g := range groups {
		group, err := userClient.Groups().Get(context.Background(), g, metav1.GetOptions{})
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
	removedGroups := sets.NewString("group2", "group3")

	_, err = tokenrequest.RequestTokenWithChallengeHandlers(kubeConfig, createChallengeHandler(username, "password42"))
	require.NoError(t, err)

	groupList, err := userClient.Groups().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	for _, g := range groupList.Items {
		require.False(t, removedGroups.Has(g.Name), "group %q is still present but should have been removed\n%v", g.Name, g)
	}
}
