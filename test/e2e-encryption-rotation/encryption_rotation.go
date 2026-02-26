package e2e_encryption_rotation

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	g "github.com/onsi/ginkgo/v2"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/configobservercontroller"
	testlibrary "github.com/openshift/cluster-authentication-operator/test/library"
	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestEncryptionRotation [Timeout:3h]", func() {
		testEncryptionRotation(g.GinkgoTB())
	})
})

// testEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func testEncryptionRotation(t testing.TB) {
	ctx := context.TODO()
	testlibrary.TestEncryptionRotation(t, library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       operatorencryption.DefaultTargetGRs,
			AssertFunc:                      operatorencryption.AssertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, _ string) runtime.Object {
			return operatorencryption.CreateAndStoreTokenOfLife(ctx, t, operatorencryption.GetClients(t))
		},
		GetRawResourceFunc: func(t testing.TB, clientSet library.ClientSet, _ string) string {
			return operatorencryption.GetRawTokenOfLife(t, clientSet)
		},
		UnsupportedConfigFunc: func(rawUnsupportedEncryptionCfg []byte) error {
			cs := operatorencryption.GetClients(t)
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
		EncryptionProvider: configv1.EncryptionType("aescbc"),
	})
}
