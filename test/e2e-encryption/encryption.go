package e2eencryption

import (
	"context"
	"fmt"
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	testlibrary "github.com/openshift/cluster-authentication-operator/test/library"
	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestEncryptionTypeIdentity", func() {
		testEncryptionTypeIdentity(g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTypeUnset", func() {
		testEncryptionTypeUnset(g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTurnOnAndOff [Timeout:3h]", func() {
		testEncryptionTurnOnAndOff(g.GinkgoTB())
	})
})

func testEncryptionTypeIdentity(t testing.TB) {
	testlibrary.TestEncryptionTypeIdentity(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       operatorencryption.DefaultTargetGRs,
		AssertFunc:                      operatorencryption.AssertTokens,
	})
}

func testEncryptionTypeUnset(t testing.TB) {
	testlibrary.TestEncryptionTypeUnset(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       operatorencryption.DefaultTargetGRs,
		AssertFunc:                      operatorencryption.AssertTokens,
	})
}

func testEncryptionTurnOnAndOff(t testing.TB) {
	testlibrary.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       operatorencryption.DefaultTargetGRs,
			AssertFunc:                      operatorencryption.AssertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, namespace string) runtime.Object {
			return operatorencryption.CreateAndStoreTokenOfLife(context.TODO(), t, operatorencryption.GetClients(t))
		},
		AssertResourceEncryptedFunc:    operatorencryption.AssertTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: operatorencryption.AssertTokenOfLifeNotEncrypted,
		ResourceFunc:                   func(t testing.TB, _ string) runtime.Object { return operatorencryption.TokenOfLife(t) },
		ResourceName:                   "TokenOfLife",
		EncryptionProvider:             configv1.EncryptionType("aescbc"),
	})
}
