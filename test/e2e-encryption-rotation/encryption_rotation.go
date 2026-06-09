package e2e_encryption_rotation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"

	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/configobservercontroller"
	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestEncryptionRotation [Timeout:3h]", func() {
		testEncryptionRotation(g.GinkgoTB())
	})
})

// testEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encryption.Reason" in the operator's configuration file
func testEncryptionRotation(t testing.TB) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	t.Cleanup(cancel)
	library.TestEncryptionRotation(ctx, t, library.RotationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
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
		EncryptionProvider: library.EncryptionProvider{
			APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC},
		},
		ForceRotationFunc: library.StaticEncryptionForceRotation(func(rawUnsupportedEncryptionCfg []byte) error {
			cs := operatorencryption.GetClients(t)
			return retry.RetryOnConflict(retry.DefaultRetry, func() error {
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
			})
		}),
		WaitForRotationCompleteFunc: library.WaitForNextEncryptionKeyRotation(),
	})
}
