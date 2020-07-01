package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestTemplatesConfig(t *testing.T) {
	kubeConfig := e2e.NewClientConfigForTest(t)

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)
	configClient, err := configclient.NewForConfig(kubeConfig)
	require.NoError(t, err)
	routeClient, err := routeclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	configSecretsClient := kubeClient.CoreV1().Secrets("openshift-config")

	cleanup := createSecret(t, configSecretsClient, "login", "login.html", "login test")
	defer cleanup()
	cleanup = createSecret(t, configSecretsClient, "providers", "providers.html", "provider selection test")
	defer cleanup()
	cleanup = createSecret(t, configSecretsClient, "error", "errors.html", "error test")
	defer cleanup()
	cleanup = createSecret(t, configSecretsClient, "htpasswd1", "htpasswd", "test:$2y$05$9Co/ojOvEs6IZUTxAdlHbO8leelkkmcwPMtlGTHFkxcTLrC86EbLG") // test:password
	defer cleanup()

	oauthConfig, err := configClient.ConfigV1().OAuths().Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	oauthConfigCopy := oauthConfig.DeepCopy()

	oauthConfigCopy.Spec.Templates.Login.Name = "login"
	oauthConfigCopy.Spec.Templates.ProviderSelection.Name = "providers"
	oauthConfigCopy.Spec.Templates.Error.Name = "error"

	oauthConfigCopy.Spec.IdentityProviders = []configv1.IdentityProvider{
		{
			Name: "super duper production-ready htpasswd idp",
			IdentityProviderConfig: configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeHTPasswd,
				HTPasswd: &configv1.HTPasswdIdentityProvider{
					FileData: configv1.SecretNameReference{
						Name: "htpasswd1",
					},
				},
			},
		},
	}

	_, err = configClient.ConfigV1().OAuths().Update(context.TODO(), oauthConfigCopy, metav1.UpdateOptions{})
	require.NoError(t, err)
	defer func() {
		oauthConfigNew, err := configClient.ConfigV1().OAuths().Get(context.TODO(), "cluster", metav1.GetOptions{})
		require.NoError(t, err)

		oauthConfigNew.Spec.IdentityProviders = oauthConfig.Spec.IdentityProviders
		oauthConfigNew.Spec.Templates = oauthConfig.Spec.Templates

		_, err = configClient.ConfigV1().OAuths().Update(context.TODO(), oauthConfigNew, metav1.UpdateOptions{})
		require.NoError(t, err)
	}()

	// wait for new rollout
	err = e2e.WaitForClusterOperatorProgressing(t, configClient.ConfigV1(), "authentication")
	require.NoError(t, err, "authentication operator never became progressing")

	err = e2e.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient.ConfigV1(), "authentication")
	require.NoError(t, err, "failed to wait for the authentication operator to become available")

	route, err := routeClient.RouteV1().Routes("openshift-authentication").Get(context.TODO(), "oauth-openshift", metav1.GetOptions{})
	require.NoError(t, err)
	oauthURL, err := url.Parse("https://" + route.Spec.Host)
	require.NoError(t, err)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // we don't care about certs in this test
			},
		},
	}
	oauthURL.Path = "/oauth/token/request" // should redirect to where the providers are
	resp, err := httpClient.Get(oauthURL.String())
	require.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "provider selection test")

	// modify URL to go to the IdP login
	oauthURL.Path = "/oauth/token/display"
	oauthURL.RawQuery = fmt.Sprintf("client_id=openshift-browser-client&idp=super+duper+production-ready+htpasswd+idp&redirect_uri=%s&response_type=code", url.QueryEscape(oauthURL.String()))
	oauthURL.Path = "/oauth/authorize"
	resp, err = httpClient.Get(oauthURL.String())
	require.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "login test")
}

func createSecret(t *testing.T, secrets corev1client.SecretInterface, name, key, content string) func() {
	_, err := secrets.Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: map[string][]byte{
			key: []byte(content),
		},
	}, metav1.CreateOptions{})

	require.NoError(t, err)

	return func() {
		if err := secrets.Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
			t.Logf("failed to remove secret openshif-config/%s: %v", name, err)
		}
	}
}
