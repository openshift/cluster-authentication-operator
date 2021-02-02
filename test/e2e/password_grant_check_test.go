package e2e

import (
	"context"
	"math/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/openshift/cluster-authentication-operator/test/library"
	test "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestGitLabAsOIDCPasswordGrantCheck(t *testing.T) {
	kubeConfig := test.NewClientConfigForTest(t)

	kubeClients, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	_, idpName, cleanups := test.AddGitlabIDP(t, kubeConfig)
	defer library.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	config, err := library.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	gitlabIDPConfig := library.GetIDPByName(config, idpName)
	require.NotNil(t, gitlabIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

	require.Equal(t, true, gitlabIDPConfig.UseAsChallenger, "gitlab is not configured as challenger")
}

func TestKeycloakAsOIDCPasswordGrantCheck(t *testing.T) {
	testContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeConfig := test.NewClientConfigForTest(t)

	kubeClients, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	configClient, err := configv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	_, idpName, cleanups := test.AddKeycloakIDP(t, kubeConfig)
	defer library.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	config, err := library.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	kcIDPConfig := library.GetIDPByName(config, idpName)
	require.NotNil(t, kcIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

	require.Equal(t, false, kcIDPConfig.UseAsChallenger, "keycloak is configured as challenger but it should not be")

	oauthConfig, err := configClient.OAuths().Get(testContext, "cluster", v1.GetOptions{})
	require.NoError(t, err)

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

	kcClient := library.KeycloakClientFor(t, transport, configIDP.OpenID.Issuer, "master")
	err = kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")
	require.NoError(t, err)

	client, err := kcClient.GetClientByClientID(configIDP.OpenID.ClientID)
	require.NoError(t, err)

	err = kcClient.UpdateClientDirectAccessGrantsEnabled(client["id"].(string), true)
	require.NoError(t, err)

	// bump the configured secret since the operator caches the password grant check
	// based on it
	configSecretName := configIDP.OpenID.ClientSecret.Name
	configSecret, err := kubeClients.CoreV1().Secrets("openshift-config").Get(testContext, configSecretName, v1.GetOptions{})
	require.NoError(t, err)

	if configSecret.Annotations == nil {
		configSecret.Annotations = map[string]string{}
	}
	configSecret.Annotations["bumped"] = strconv.FormatUint(rand.Uint64(), 10)
	_, err = kubeClients.CoreV1().Secrets("openshift-config").Update(testContext, configSecret, v1.UpdateOptions{})
	require.NoError(t, err)

	err = library.WaitForOperatorToPickUpChanges(t, configClient, "authentication")
	require.NoError(t, err)

	config, err = library.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	kcIDPConfig = library.GetIDPByName(config, idpName)
	require.NotNil(t, kcIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

	require.Equal(t, true, kcIDPConfig.UseAsChallenger, "keycloak is not configured as challenger but it should be")
}
