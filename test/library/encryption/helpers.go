package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/clientv3"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	kubecmdapi "k8s.io/client-go/tools/clientcmd/api"

	oauthapiv1 "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

type ClientSet struct {
	OperatorClient operatorv1client.AuthenticationInterface
	TokenClient    oauthclient.OAuthAccessTokensGetter
}

func GetClientsFor(t testing.TB, kubeConfig *rest.Config) ClientSet {
	t.Helper()

	operatorClient, err := operatorv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	oc, err := oauthclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	return ClientSet{OperatorClient: operatorClient.Authentications(), TokenClient: oc}
}

func GetClients(t testing.TB) ClientSet {
	t.Helper()

	kubeConfig := NewClientConfigForTest(t)

	return GetClientsFor(t, kubeConfig)
}

// NewClientConfigForTest returns a config configured to connect to the api server
func NewClientConfigForTest(t testing.TB) *rest.Config {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: kubecmdapi.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		fmt.Printf("Found configuration for host %v.\n", config.Host)
	}
	require.NoError(t, err)
	return config
}

func CreateAndStoreTokenOfLife(ctx context.Context, t testing.TB, cs ClientSet) runtime.Object {
	t.Helper()
	{
		oldTokenOfLife, err := cs.TokenClient.OAuthAccessTokens().Get(ctx, "token-aaaaaaaa-of-aaaaaaaa-life-aaaaaaaa", metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			t.Errorf("Failed to check if the route already exists, due to %v", err)
		}
		if len(oldTokenOfLife.Name) > 0 {
			t.Log("The access token already exist, removing it first")
			err := cs.TokenClient.OAuthAccessTokens().Delete(ctx, oldTokenOfLife.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to delete %s, err %v", oldTokenOfLife.Name, err)
			}
		}
	}
	t.Logf("Creating %q at cluster scope level", "token-aaaaaaaa-of-aaaaaaaa-life-aaaaaaaa")
	rawTokenOfLife := TokenOfLife(t)
	tokenOfLife, err := cs.TokenClient.OAuthAccessTokens().Create(ctx, rawTokenOfLife.(*oauthapiv1.OAuthAccessToken), metav1.CreateOptions{})
	require.NoError(t, err)
	return tokenOfLife
}

func GetRawTokenOfLife(t testing.TB, clientSet library.ClientSet) string {
	t.Helper()
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tokenOfLifeEtcdPrefix := fmt.Sprintf("/openshift.io/oauth/accesstokens/%s", "token-aaaaaaaa-of-aaaaaaaa-life-aaaaaaaa")
	resp, err := clientSet.Etcd.Get(timeout, tokenOfLifeEtcdPrefix, clientv3.WithPrefix())
	require.NoError(t, err)

	if len(resp.Kvs) != 1 {
		t.Errorf("Expected to get a single key from etcd, got %d", len(resp.Kvs))
	}

	return string(resp.Kvs[0].Value)
}

func TokenOfLife(t testing.TB) runtime.Object {
	t.Helper()
	return &oauthapiv1.OAuthAccessToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: "token-aaaaaaaa-of-aaaaaaaa-life-aaaaaaaa",
		},
		RefreshToken: "I have no special talents. I am only passionately curious",
		UserName:     "kube:admin",
		Scopes:       []string{"user:full"},
		RedirectURI:  "redirect.me.to.token.of.life",
		ClientName:   "console",
		UserUID:      "non-existing-user-id",
	}
}
