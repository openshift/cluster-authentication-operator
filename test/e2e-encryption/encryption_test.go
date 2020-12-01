package e2eencryption

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
	library "github.com/openshift/library-go/test/library/encryption"
)

var DefaultTargetGRs = []schema.GroupResource{
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
}

func TestEncryptionTypeIdentity(t *testing.T) {
	library.TestEncryptionTypeIdentity(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       DefaultTargetGRs,
		AssertFunc:                      assertTokens,
	})
}

func TestEncryptionTypeUnset(t *testing.T) {
	library.TestEncryptionTypeUnset(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       DefaultTargetGRs,
		AssertFunc:                      assertTokens,
	})
}

func TestEncryptionTurnOnAndOff(t *testing.T) {
	library.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       DefaultTargetGRs,
			AssertFunc:                      assertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, namespace string) runtime.Object {
			return CreateAndStoreTokenOfLife(context.TODO(), t, GetClients(t))
		},
		AssertResourceEncryptedFunc:    assertTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: assertTokenOfLifeNotEncrypted,
		ResourceFunc:                   func(t testing.TB, _ string) runtime.Object { return TokenOfLife(t) },
		ResourceName:                   "TokenOfLife",
	})
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(t *testing.T) {
	ctx := context.TODO()
	library.TestEncryptionRotation(t, library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       DefaultTargetGRs,
			AssertFunc:                      assertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, _ string) runtime.Object {
			return CreateAndStoreTokenOfLife(ctx, t, GetClients(t))
		},
		GetRawResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) string {
			return GetRawTokenOfLife(t, clientSet)
		},
		UnsupportedConfigFunc: func(rawUnsupportedEncryptionCfg []byte) error {
			cs := GetClients(t)
			authOperator, err := cs.OperatorClient.Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				return err
			}

			unsupportedConfigAsMap := map[string]interface{}{}
			if len(authOperator.Spec.UnsupportedConfigOverrides.Raw) > 0 {
				if err := json.Unmarshal(authOperator.Spec.UnsupportedConfigOverrides.Raw, &unsupportedConfigAsMap); err != nil {
					return err
				}
			}
			unsupportedEncryptionConfigAsMap := map[string]interface{}{}
			if err := json.Unmarshal(rawUnsupportedEncryptionCfg, &unsupportedEncryptionConfigAsMap); err != nil {
				return err
			}
			if err := unstructured.SetNestedMap(unsupportedConfigAsMap, unsupportedEncryptionConfigAsMap, oauthapiconfigobservercontroller.OAuthAPIServerConfigPrefix); err != nil {
				return err
			}
			rawUnsupportedCfg, err := json.Marshal(unsupportedConfigAsMap)
			if err != nil {
				return err
			}
			authOperator.Spec.UnsupportedConfigOverrides.Raw = rawUnsupportedCfg

			_, err = cs.OperatorClient.Update(ctx, authOperator, metav1.UpdateOptions{})
			return err
		},
	})
}

func assertTokens(t testing.TB, clientSet library.ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
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

func assertTokenOfLifeEncrypted(t testing.TB, clientSet library.ClientSet, rawTokenOfLife runtime.Object) {
	t.Helper()
	tokenOfLife := rawTokenOfLife.(*oauthapiv1.OAuthAccessToken)
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token not encrypted, token received from etcd have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}

func assertTokenOfLifeNotEncrypted(t testing.TB, clientSet library.ClientSet, rawTokenOfLife runtime.Object) {
	t.Helper()
	tokenOfLife := rawTokenOfLife.(*oauthapiv1.OAuthAccessToken)
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if !strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token received from etcd doesnt have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}
