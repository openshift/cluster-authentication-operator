package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/client-go/kubernetes"

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
