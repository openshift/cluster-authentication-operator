package e2e

import (
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	"k8s.io/client-go/kubernetes"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[OIDC][Serial] TestGitLabAsOIDCPasswordGrantCheck", func() {
		testGitLabAsOIDCPasswordGrantCheck(g.GinkgoTB())
	})
})

func testGitLabAsOIDCPasswordGrantCheck(t testing.TB) {
	kubeConfig := test.NewClientConfigForTest(t)

	kubeClients, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	_, idpName, cleanups := test.AddGitlabIDP(t, kubeConfig)
	defer test.IDPCleanupWrapper(func() {
		for _, c := range cleanups {
			c()
		}
	})()

	config, err := test.GrabOAuthServerConfig(kubeClients.CoreV1())
	require.NoError(t, err)

	gitlabIDPConfig := test.GetIDPByName(config, idpName)
	require.NotNil(t, gitlabIDPConfig, "did not find idp %q in the config: %#v", idpName, config)

	require.Equal(t, true, gitlabIDPConfig.UseAsChallenger, "gitlab is not configured as challenger")
}
