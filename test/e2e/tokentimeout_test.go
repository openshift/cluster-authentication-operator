package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestTokenTimeoutSyncer(t *testing.T) {
	const (
		oauthClientName = "authn-test-client"
		userName        = "someuser"
		tokenName       = "sha256~somethingthatexceedstheminimumsizelimit"
		redirectURI     = "https://someplace.somewhere"
	)

	kubeConfig := test.NewClientConfigForTest(t)

	oauthClient, err := oauthv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	userClient, err := userv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	configClient, err := configv1client.NewForConfig(kubeConfig)
	require.NoError(t, err)

	testOAuthClient, err := oauthClient.OAuthClients().Create(context.Background(),
		&oauthv1.OAuthClient{
			ObjectMeta: metav1.ObjectMeta{
				Name: oauthClientName,
			},
			RedirectURIs: []string{redirectURI},
			GrantMethod:  oauthv1.GrantHandlerAuto,
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer oauthClient.OAuthClients().Delete(context.Background(), testOAuthClient.Name, metav1.DeleteOptions{})

	user, err := userClient.Users().Create(context.Background(),
		&userv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Name: userName,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer userClient.Users().Delete(context.Background(), user.Name, metav1.DeleteOptions{})

	_, err = oauthClient.OAuthAccessTokens().Create(
		context.Background(),
		&oauthv1.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: tokenName,
			},
			ClientName:               oauthClientName,
			ExpiresIn:                86400,
			UserName:                 user.Name,
			UserUID:                  string(user.UID),
			RedirectURI:              redirectURI,
			InactivityTimeoutSeconds: 2000,
			Scopes:                   []string{"user:info"},
		},
		metav1.CreateOptions{})
	require.NoError(t, err)
	defer oauthClient.OAuthAccessTokens().Delete(context.Background(), tokenName, metav1.DeleteOptions{})

	testOAuthClient.AccessTokenInactivityTimeoutSeconds = pint32(1000)
	testOAuthClient, err = oauthClient.OAuthClients().Update(context.Background(),
		testOAuthClient,
		metav1.UpdateOptions{},
	)

	err = wait.PollImmediate(2*time.Second, 15*time.Second, func() (bool, error) {
		token, err := oauthClient.OAuthAccessTokens().Get(context.Background(), tokenName, metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to retrieve the testing token: %s", err)
			return false, nil
		}
		done := token.InactivityTimeoutSeconds < 1100
		if !done {
			t.Logf("current token inactivity seconds: %d", token.InactivityTimeoutSeconds)
		}
		return done, nil // 1100 allows for a little bit of slack before the sync
	})
	require.NoError(t, err)

	// make sure the value isn't increased back, we only do the shortening
	testOAuthClient.AccessTokenInactivityTimeoutSeconds = pint32(1500)
	testOAuthClient, err = oauthClient.OAuthClients().Update(context.Background(),
		testOAuthClient,
		metav1.UpdateOptions{},
	)

	err = wait.PollImmediate(2*time.Second, 15*time.Second, func() (bool, error) {
		token, err := oauthClient.OAuthAccessTokens().Get(context.Background(), tokenName, metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to retrieve the testing token: %s", err)
			return false, nil
		}
		return token.InactivityTimeoutSeconds >= 1500, nil
	})

	// use the global config
	testOAuthClient.AccessTokenInactivityTimeoutSeconds = nil
	testOAuthClient, err = oauthClient.OAuthClients().Update(context.Background(),
		testOAuthClient,
		metav1.UpdateOptions{},
	)

	oauthConfig, err := configClient.OAuths().Get(context.Background(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	origTimeout := oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout.DeepCopy()

	oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeout = &metav1.Duration{Duration: 500 * time.Second}
	_, err = configClient.OAuths().Update(context.Background(), oauthConfig, metav1.UpdateOptions{})
	require.NoError(t, err)

	// revert timeout back to original value on test end
	defer func() {
		config, err := configClient.OAuths().Get(context.Background(), "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to revert global timeout config: %v", err)
		}

		config.Spec.TokenConfig.AccessTokenInactivityTimeout = origTimeout
		_, err = configClient.OAuths().Update(context.Background(), config, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("failed to revert global timeout config: %v", err)
		}
	}()

	err = wait.PollImmediate(2*time.Second, 15*time.Second, func() (bool, error) {
		token, err := oauthClient.OAuthAccessTokens().Get(context.Background(), tokenName, metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to retrieve the testing token: %s", err)
			return false, nil
		}
		return token.InactivityTimeoutSeconds <= 700, nil
	})

}

func pint32(i int32) *int32 {
	return &i
}
