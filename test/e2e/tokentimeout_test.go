package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	oauthapi "github.com/openshift/api/oauth/v1"
	userapi "github.com/openshift/api/user/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

const (
	defaultAccessTokenMaxAgeSeconds = 86400
)

func TestTokenInactivityTimeout(t *testing.T) {
	t.SkipNow()
	kubeConfig := test.NewClientConfigForTest(t)

	userClient := userclient.NewForConfigOrDie(kubeConfig)
	oauthClientClient := oauthclient.NewForConfigOrDie(kubeConfig)
	configClient := configclient.NewForConfigOrDie(kubeConfig)

	transport := &http.Transport{
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

	testTokenValidity := func(t *testing.T, req *http.Request, statusCode int, bearerToken, errMsg string) {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		if resp.StatusCode != statusCode {
			t.Fatalf("%s. Received status %q", errMsg, resp.Status)
		}
	}

	// This checks that
	// 1. Token with timeout does not work after it times out
	// 2. Token without timeout works at anytime
	testTokenTimeouts := func(t *testing.T, tokenWithTimeout, tokenWithoutTimeout string, timeout time.Duration) {
		req, err := http.NewRequest(http.MethodGet, kubeConfig.Host+"/apis/user.openshift.io/v1/users/~", &bytes.Buffer{})
		require.NoError(t, err)

		time.Sleep(timeout + 10*time.Second)

		testTokenValidity(t, req, http.StatusUnauthorized, tokenWithTimeout, "accessing token after it timed out should not work")
		testTokenValidity(t, req, http.StatusOK, tokenWithoutTimeout, "token with out timeout should work")
	}

	// This checks that
	// 1. Token with timeout works immediately after they are created
	// 2. Token with timeout works anytime before it times out
	// 3. Token with timeout does not work after it times out
	// 4. Token without timeout works at anytime
	testInactivityTimeoutScenarios := func(t *testing.T, tokenWithTimeout, tokenWithoutTimeout string, timeout time.Duration) {
		req, err := http.NewRequest(http.MethodGet, kubeConfig.Host+"/apis/user.openshift.io/v1/users/~", &bytes.Buffer{})
		require.NoError(t, err)

		testTokenValidity(t, req, http.StatusOK, tokenWithTimeout, "accessing token before it timed out should work")
		testTokenValidity(t, req, http.StatusOK, tokenWithoutTimeout, "token with out timeout should work")

		time.Sleep(120 * time.Second)

		testTokenValidity(t, req, http.StatusOK, tokenWithTimeout, "accessing token before it timed out should work")
		testTokenValidity(t, req, http.StatusOK, tokenWithoutTimeout, "token with out timeout should work")

		time.Sleep(timeout + 10*time.Second)

		testTokenValidity(t, req, http.StatusUnauthorized, tokenWithTimeout, "accessing token after it timed out should not work")
		testTokenValidity(t, req, http.StatusOK, tokenWithoutTimeout, "token with out timeout should work")
	}

	configInactivityTimeout := int32(420) // 420 is the minimum possible timeout + 2min to distinguish it from oauth client timeouts
	oauthClientTimeout := int32(300)      // 300 is the minimum possible timeout

	// No OAuthClient timeout and no OAuth config timeout.
	t.Run("without-inactivity-timeout", func(t *testing.T) {
		checkTokenAccess(t, userClient, oauthClientClient, configInactivityTimeout, nil, testTokenTimeouts)
	})

	// With only OAuth config timeout.
	t.Run("with-inactivity-timeout", func(t *testing.T) {
		updateOAuthConfigInactivityTimeout(t, configClient, &metav1.Duration{Duration: time.Duration(configInactivityTimeout) * time.Second})

		err := test.WaitForClusterOperatorProgressing(t, configClient, "authentication")
		require.NoError(t, err, "authentication operator never became progressing")
		err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient, "authentication")
		require.NoError(t, err)
		client := kubernetes.NewForConfigOrDie(kubeConfig)
		waitOAuthServerReplicasReady(t, client)

		checkTokenAccess(t, userClient, oauthClientClient, configInactivityTimeout, nil, testInactivityTimeoutScenarios)
	})

	// With both OAuth config timeout and OAuthClient timeout.
	t.Run("with-client-timeout", func(t *testing.T) {
		checkTokenAccess(t, userClient, oauthClientClient, configInactivityTimeout, &oauthClientTimeout, testInactivityTimeoutScenarios)
	})

	// No OAuthClient timeout and no OAuth config timeout.
	t.Run("unset-inactivity-timeout-client-timeout", func(t *testing.T) {
		updateOAuthConfigInactivityTimeout(t, configClient, nil)

		err := test.WaitForClusterOperatorProgressing(t, configClient, "authentication")
		require.NoError(t, err, "authentication operator never became progressing")
		err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient, "authentication")
		require.NoError(t, err)
		client := kubernetes.NewForConfigOrDie(kubeConfig)
		waitOAuthServerReplicasReady(t, client)

		checkTokenAccess(t, userClient, oauthClientClient, configInactivityTimeout, nil, testTokenTimeouts)
	})

}

func checkTokenAccess(t *testing.T,
	userClient *userclient.UserV1Client,
	oauthClientClient *oauthclient.OauthV1Client,
	configInactivityTimeout int32, oauthClientTimeout *int32,
	testAccess func(*testing.T, string, string, time.Duration)) {
	// Create the user, identity, oauthclient and oauthaccesstoken objects needed for authentication using Bearer tokens.
	subTestNameHierarchy := strings.Split(t.Name(), "/")
	prefix := subTestNameHierarchy[len(subTestNameHierarchy)-1] + "-"

	userName := prefix + "testuser"
	idpName := "htpasswd"
	oauthClientName := prefix + "oauthclient"
	redirectURIs := []string{"https://localhost"}
	identityName := idpName + ":" + userName

	uid, cleanup := createUser(t, userClient, userName, identityName)
	defer cleanup()

	cleanup = createIdentity(t, userClient, userName, identityName, idpName, uid)
	defer cleanup()

	cleanup = createOAuthClient(t, oauthClientClient, oauthClientName, redirectURIs, oauthClientTimeout)
	defer cleanup()

	tokenWithTimeoutClear, tokenWithTimeoutHash := test.GenerateOAuthTokenPair()
	tokenWithTimeout := &oauthapi.OAuthAccessToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: tokenWithTimeoutHash,
		},
		ClientName:               oauthClientName,
		ExpiresIn:                defaultAccessTokenMaxAgeSeconds,
		Scopes:                   []string{"user:full"},
		RedirectURI:              redirectURIs[0],
		UserName:                 userName,
		UserUID:                  string(uid),
		AuthorizeToken:           "mJOQ7Es5l9V7WYDl0bvl3E_hRjnJ21ZZxXH6YZj3yeS",
		InactivityTimeoutSeconds: 60,
	}

	tokenWithoutTimeoutClear, tokenWithoutTimeoutHash := test.GenerateOAuthTokenPair()
	tokenWithoutTimeout := &oauthapi.OAuthAccessToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: tokenWithoutTimeoutHash,
		},
		ClientName:     oauthClientName,
		ExpiresIn:      defaultAccessTokenMaxAgeSeconds,
		Scopes:         []string{"user:full"},
		RedirectURI:    redirectURIs[0],
		UserName:       userName,
		UserUID:        string(uid),
		AuthorizeToken: "mJOQ7Es5l9V7WYDl0bvl3E_hRjnJ21ZZxXH6YZj3yeT",
	}

	// create tokens with and without timeouts
	for _, accessToken := range []*oauthapi.OAuthAccessToken{tokenWithTimeout, tokenWithoutTimeout} {
		_, err := oauthClientClient.OAuthAccessTokens().Create(context.TODO(), accessToken, metav1.CreateOptions{})
		require.NoError(t, err)
		defer func(name string) {
			if err := oauthClientClient.OAuthAccessTokens().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
				t.Logf("%v", err)
			}
		}(accessToken.Name)
	}

	expectedInactivityTimeout := configInactivityTimeout
	if oauthClientTimeout != nil {
		expectedInactivityTimeout = *oauthClientTimeout
	}
	testAccess(t, tokenWithTimeoutClear, tokenWithoutTimeoutClear, time.Duration(expectedInactivityTimeout)*time.Second)
}

func updateOAuthConfigInactivityTimeout(t *testing.T, client *configclient.ConfigV1Client, duration *metav1.Duration) {
	oauthConfig, err := client.OAuths().Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout = duration

	err = wait.PollImmediate(300*time.Millisecond, 2*time.Second, func() (bool, error) {
		_, err := client.OAuths().Update(context.TODO(), oauthConfig, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("failed to update oauth cluster config: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)
}

func createUser(t *testing.T, userClient *userclient.UserV1Client, userName, identity string) (types.UID, func()) {
	user := &userapi.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: userName,
		},
		Identities: []string{identity},
	}

	err := wait.PollImmediate(300*time.Millisecond, 2*time.Second, func() (bool, error) {
		var err error
		user, err = userClient.Users().Create(context.TODO(), user, metav1.CreateOptions{})
		if err != nil {
			t.Logf("failed to create user: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)
	return user.UID, func() {
		if err := userClient.Users().Delete(context.TODO(), userName, metav1.DeleteOptions{}); err != nil {
			t.Logf("%v", err)
		}
	}
}

func createIdentity(t *testing.T, userClient *userclient.UserV1Client, userName, identityName, idpName string, uid types.UID) func() {
	identity := &userapi.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name: identityName,
		},
		ProviderName:     idpName,
		ProviderUserName: userName,
		User: corev1.ObjectReference{
			Name: userName,
			UID:  uid,
		},
	}

	err := wait.PollImmediate(300*time.Second, 2*time.Second, func() (bool, error) {
		_, err := userClient.Identities().Create(context.TODO(), identity, metav1.CreateOptions{})
		if err != nil {
			t.Logf("failed to create user identity: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)
	return func() {
		if err := userClient.Identities().Delete(context.TODO(), identity.Name, metav1.DeleteOptions{}); err != nil {
			t.Logf("%v", err)
		}
	}
}

func createOAuthClient(t *testing.T, oauthClientClient *oauthclient.OauthV1Client, oauthClientName string, redirectURIs []string, timeout *int32) func() {
	oauthClient := &oauthapi.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: oauthClientName,
		},
		Secret:                              "the-secret-for-oauth-client",
		RedirectURIs:                        redirectURIs,
		GrantMethod:                         "auto",
		AccessTokenInactivityTimeoutSeconds: timeout,
	}

	err := wait.PollImmediate(300*time.Millisecond, 2*time.Second, func() (bool, error) {
		_, err := oauthClientClient.OAuthClients().Create(context.TODO(), oauthClient, metav1.CreateOptions{})
		if err != nil {
			t.Logf("failed to create oauth client: %v", err)
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)
	return func() {
		if err := oauthClientClient.OAuthClients().Delete(context.TODO(), oauthClient.Name, metav1.DeleteOptions{}); err != nil {
			t.Logf("%v", err)
		}
	}
}

func waitOAuthServerReplicasReady(t *testing.T, kubeClient kubernetes.Interface) {
	t.Logf("waiting all oauth-apiserver replicas to be updated and ready")

	err := wait.PollImmediate(time.Second, 10*time.Minute, func() (bool, error) {
		deployment, err := kubeClient.AppsV1().Deployments("openshift-oauth-apiserver").Get(context.Background(), "apiserver", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to retrieve oauth-apiserver's deployment: %v", err)
			return false, nil
		}

		var requestedReplicas int32 = 1
		if specReplicas := deployment.Spec.Replicas; specReplicas != nil {
			requestedReplicas = *specReplicas
		}
		return requestedReplicas == deployment.Status.ReadyReplicas && deployment.Status.UpdatedReplicas == requestedReplicas, nil
	})
	require.NoError(t, err)

}
