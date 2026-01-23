package library

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	psapi "k8s.io/pod-security-admission/api"
)

// NewClientConfigForTest returns a config configured to connect to the api server
func NewClientConfigForTest(t testing.TB) *rest.Config {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: api.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		fmt.Printf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	return config
}

// GenerateOAuthTokenPair returns two tokens to use with OpenShift OAuth-based authentication.
// The first token is a private token meant to be used as a Bearer token to send
// queries to the API, the second token is a hashed token meant to be stored in
// the database.
func GenerateOAuthTokenPair() (privToken, pubToken string) {
	const sha256Prefix = "sha256~"
	randomToken := fmt.Sprintf("nottoorandom%d", mathrand.Int())
	hashed := sha256.Sum256([]byte(randomToken))
	return sha256Prefix + string(randomToken), sha256Prefix + base64.RawURLEncoding.EncodeToString(hashed[:])
}

type testNamespaceBuilder struct {
	ns *corev1.Namespace
}

func NewTestNamespaceBuilder(namePrefix string) *testNamespaceBuilder {
	return &testNamespaceBuilder{
		ns: &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: namePrefix,
				Labels: map[string]string{
					psapi.EnforceLevelLabel:                          string(psapi.LevelRestricted),
					"security.openshift.io/scc.podSecurityLabelSync": "false",
				},
			},
		},
	}
}

func (b *testNamespaceBuilder) WithLabels(labels map[string]string) *testNamespaceBuilder {
	for k, v := range labels {
		b.ns.Labels[k] = v
	}
	return b
}

func (b *testNamespaceBuilder) WithPSaEnforcement(level psapi.Level) *testNamespaceBuilder {
	b.ns.Labels[psapi.EnforceLevelLabel] = string(level)
	return b
}

func (b *testNamespaceBuilder) WithRestrictedPSaEnforcement() *testNamespaceBuilder {
	return b.WithPSaEnforcement(psapi.LevelRestricted)
}

func (b *testNamespaceBuilder) WithBaselinePSaEnforcement() *testNamespaceBuilder {
	return b.WithPSaEnforcement(psapi.LevelBaseline)
}

func (b *testNamespaceBuilder) WithPrivilegedPSaEnforcement() *testNamespaceBuilder {
	return b.WithPSaEnforcement(psapi.LevelPrivileged)
}

func (b *testNamespaceBuilder) Create(t testing.TB, kubeClient corev1client.NamespaceInterface) string {
	ns, err := kubeClient.Create(context.Background(), b.ns, metav1.CreateOptions{})
	require.NoError(t, err)

	return ns.Name
}
