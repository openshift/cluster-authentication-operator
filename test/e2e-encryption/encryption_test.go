package e2eencryption

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

var DefaultTargetGRs = []schema.GroupResource{
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
	// TODO: remove route in 4.7, in 4.6 OAS-O is managing the encryption configuration for CAO
	{Group: "route.openshift.io", Resource: "routes"},
}

func TestEncryptionTypeIdentity(t *testing.T) {
	// TODO: bring back when https://github.com/openshift/cluster-openshift-apiserver-operator/pull/348 is merged
	t.Skip()
	library.TestEncryptionTypeIdentity(t, library.BasicScenario{
		Namespace: "openshift-config-managed",
		// TODO: update the LabelSelector in 4.7, in 4.6 OAS-O is managing the encryption configuration for CAO
		// LabelSelector:                "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver"
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       DefaultTargetGRs,
		AssertFunc:                      AssertTokens,
	})
}

func TestEncryptionTypeUnset(t *testing.T) {
	// TODO: bring back when https://github.com/openshift/cluster-openshift-apiserver-operator/pull/348 is merged
	t.Skip()
	library.TestEncryptionTypeUnset(t, library.BasicScenario{
		Namespace: "openshift-config-managed",
		// TODO: update the LabelSelector in 4.7, in 4.6 OAS-O is managing the encryption configuration for CAO
		// LabelSelector:                "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver"
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       DefaultTargetGRs,
		AssertFunc:                      AssertTokens,
	})
}

func TestEncryptionTurnOnAndOff(t *testing.T) {
	// TODO: bring back when https://github.com/openshift/cluster-openshift-apiserver-operator/pull/348 is merged
	t.Skip()
	library.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace: "openshift-config-managed",
			// TODO: update the LabelSelector in 4.7, in 4.6 OAS-O is managing the encryption configuration for CAO
			// LabelSelector:                "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver"
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       DefaultTargetGRs,
			AssertFunc:                      AssertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, namespace string) runtime.Object {
			return CreateAndStoreTokenOfLife(context.TODO(), t, GetClients(t))
		},
		AssertResourceEncryptedFunc:    AssertTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: AssertTokenOfLifeNotEncrypted,
		ResourceFunc:                   func(t testing.TB, _ string) runtime.Object { return TokenOfLife(t) },
		ResourceName:                   "TokenOfLife",
	})
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(t *testing.T) {
	// TODO: bring back when https://github.com/openshift/cluster-openshift-apiserver-operator/pull/348 is merged
	t.Skip()
	ctx := context.TODO()
	library.TestEncryptionRotation(t, library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace: "openshift-config-managed",
			// TODO: update the LabelSelector in 4.7, in 4.6 OAS-O is managing the encryption configuration for CAO
			// LabelSelector:                "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver"
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       DefaultTargetGRs,
			AssertFunc:                      AssertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, _ string) runtime.Object {
			return CreateAndStoreTokenOfLife(ctx, t, GetClients(t))
		},
		GetRawResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) string {
			return GetRawTokenOfLife(t, clientSet)
		},
		UnsupportedConfigFunc: func(raw []byte) error {
			cs := GetClients(t)
			apiServerOperator, err := cs.OperatorClient.Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				return err
			}
			apiServerOperator.Spec.UnsupportedConfigOverrides.Raw = raw
			_, err = cs.OperatorClient.Update(ctx, apiServerOperator, metav1.UpdateOptions{})
			return err
		},
	})
}

func AssertTokens(t testing.TB, clientSet library.ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertAccessTokens(t, clientSet.Etcd, string(expectedMode))
	assertAuthTokens(t, clientSet.Etcd, string(expectedMode))
	library.AssertLastMigratedKey(t, clientSet.Kube, DefaultTargetGRs, namespace, labelSelector)
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
