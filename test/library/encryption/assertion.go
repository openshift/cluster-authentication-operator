package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

var DefaultTargetGRs = []schema.GroupResource{
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
}

func AssertTokens(t testing.TB, clientSet library.ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertAccessTokens(t, clientSet.Etcd, string(expectedMode))
	assertAuthTokens(t, clientSet.Etcd, string(expectedMode))
	library.AssertLastMigratedKey(t, clientSet.Kube, DefaultTargetGRs, namespace, labelSelector)
}

func AssertTokenOfLifeEncrypted(t testing.TB, clientSet library.ClientSet, rawTokenOfLife runtime.Object) {
	t.Helper()
	tokenOfLife := rawTokenOfLife.(*oauthapiv1.OAuthAccessToken)
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token not encrypted, token received from etcd have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}

func AssertTokenOfLifeNotEncrypted(t testing.TB, clientSet library.ClientSet, rawTokenOfLife runtime.Object) {
	t.Helper()
	tokenOfLife := rawTokenOfLife.(*oauthapiv1.OAuthAccessToken)
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if !strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token received from etcd doesnt have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}

func assertAccessTokens(t testing.TB, etcdClient library.EtcdClient, expectedMode string) {
	t.Logf("Checking if all OauthAccessTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAccessTokens, err := library.VerifyResources(t, etcdClient, "/openshift.io/oauth/accesstokens/", expectedMode, true)
	t.Logf("Verified %d OauthAccessTokens", totalAccessTokens)
	require.NoError(t, err)
}

func assertAuthTokens(t testing.TB, etcdClient library.EtcdClient, expectedMode string) {
	t.Logf("Checking if all OAuthAuthorizeTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAuthTokens, err := library.VerifyResources(t, etcdClient, "/openshift.io/oauth/authorizetokens/", expectedMode, true)
	t.Logf("Verified %d OAuthAuthorizeTokens", totalAuthTokens)
	require.NoError(t, err)
}
