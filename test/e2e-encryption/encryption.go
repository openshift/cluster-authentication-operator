package e2e_encryption

import (
	"context"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestEncryptionTypeIdentity", func(ctx context.Context) {
		testEncryptionTypeIdentity(ctx, g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTypeUnset", func(ctx context.Context) {
		testEncryptionTypeUnset(ctx, g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTurnOnAndOff [Timeout:60m]", func(ctx context.Context) {
		testEncryptionTurnOnAndOff(ctx, g.GinkgoTB())
	})
})

func testEncryptionTypeIdentity(ctx context.Context, tt testing.TB) {
	library.TestEncryptionTypeIdentity(ctx, tt, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
		EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       library.WellKnownAuthTargetGRs,
		AssertFunc:                      library.AssertWellKnownTokens,
	})
}

func testEncryptionTypeUnset(ctx context.Context, tt testing.TB) {
	library.TestEncryptionTypeUnset(ctx, tt, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
		EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       library.WellKnownAuthTargetGRs,
		AssertFunc:                      library.AssertWellKnownTokens,
	})
}

func testEncryptionTurnOnAndOff(ctx context.Context, tt testing.TB) {
	library.TestEncryptionTurnOnAndOff(ctx, tt, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
			EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, _ string) runtime.Object {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			t.Cleanup(cancel)
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, library.GetClients(t))
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownTokenOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownTokenOfLife,
		ResourceName:                   "TokenOfLife",
		EncryptionProvider: library.EncryptionProvider{
			APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionType("aescbc")},
		},
	})
}
