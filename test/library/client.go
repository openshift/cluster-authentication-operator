package library

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	psapi "k8s.io/pod-security-admission/api"

	configclient "github.com/openshift/client-go/config/clientset/versioned"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
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

// TestClients holds commonly used Kubernetes and OpenShift clients for e2e tests
type TestClients struct {
	KubeClient     kubernetes.Interface
	ConfigClient   *configclient.Clientset
	OperatorClient *operatorclient.Clientset
	RouteClient    *routeclient.Clientset
	OAuthClient    *oauthclient.Clientset
	UserClient     userclient.UserV1Interface
}

// NewTestClients creates a TestClients struct with all common clients initialized
func NewTestClients(t testing.TB) *TestClients {
	kubeConfig := NewClientConfigForTest(t)

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)

	configClient, err := configclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	operatorClient, err := operatorclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	routeClient, err := routeclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	oauthClient, err := oauthclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	userClient, err := userclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	return &TestClients{
		KubeClient:     kubeClient,
		ConfigClient:   configClient,
		OperatorClient: operatorClient,
		RouteClient:    routeClient,
		OAuthClient:    oauthClient,
		UserClient:     userClient,
	}
}

// NewInsecureHTTPClient creates an HTTP client that skips TLS verification for testing
func NewInsecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewInsecureHTTPTransport(),
	}
}

// NewInsecureHTTPTransport creates an HTTP transport that skips TLS verification for testing
func NewInsecureHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
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
