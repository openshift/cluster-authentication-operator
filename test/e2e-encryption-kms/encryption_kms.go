package e2eencryptionkms

import (
	"context"
	"math/rand/v2"
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	testlibrary "github.com/openshift/cluster-authentication-operator/test/library"
	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
	librarykms "github.com/openshift/library-go/test/library/encryption/kms"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestKMSEncryptionOnOff [Timeout:2h]", func() {
		testKMSEncryptionOnOff(g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestKMSEncryptionProvidersMigration [Timeout:2h]", func() {
		testKMSEncryptionProvidersMigration(g.GinkgoTB())
	})
})

// testKMSEncryptionOnOff tests KMS encryption on/off cycle.
// This test:
// 1. Deploys the mock KMS plugin
// 2. Creates a test OAuth access token (TokenOfLife)
// 3. Enables KMS encryption
// 4. Verifies token is encrypted
// 5. Disables encryption (Identity)
// 6. Verifies token is NOT encrypted
// 7. Re-enables KMS encryption
// 8. Verifies token is encrypted again
// 9. Disables encryption (Identity) again
// 10. Verifies token is NOT encrypted again
func testKMSEncryptionOnOff(t testing.TB) {
	ctx := context.Background()
	testClients := testlibrary.NewTestClients(t)

	// Check if KMS encryption feature gates are enabled, skip if not
	testlibrary.CheckFeatureGatesOrSkip(t, ctx, testClients.ConfigClient, features.FeatureGateKMSEncryption, features.FeatureGateKMSEncryptionProvider)

	// TODO: Remove this skip once the authentication operator fully supports KMS encryption.
	// Currently, while the API accepts encryption.type: "KMS" and the operator mounts the KMS
	// plugin socket, it does not generate the EncryptionConfiguration with KMS provider stanza.
	// This causes tests to timeout waiting for encryption keys to be created and migration to complete.
	// See: https://issues.redhat.com/browse/AUTH-XXX
	t.Skip("Skipping KMS encryption test: operator implementation is incomplete")

	// Deploy the mock KMS plugin for testing.
	// NOTE: This manual deployment is only required for KMS v1. In the future,
	// the platform will manage the KMS plugins, and this code will no longer be needed.
	librarykms.DeployUpstreamMockKMSPlugin(ctx, t, library.GetClients(t).Kube, librarykms.WellKnownUpstreamMockKMSPluginNamespace, librarykms.WellKnownUpstreamMockKMSPluginImage)
	testlibrary.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
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
		EncryptionProvider:             configv1.EncryptionTypeKMS,
	})
}

// testKMSEncryptionProvidersMigration tests migration between KMS and AES encryption providers.
// This test:
// 1. Deploys the mock KMS plugin
// 2. Creates a test OAuth access token (TokenOfLife)
// 3. Randomly picks one AES encryption provider (AESGCM or AESCBC)
// 4. Shuffles the selected AES provider with KMS to create a randomized migration order
// 5. Migrates between the providers in the shuffled order
// 6. Verifies token is correctly encrypted after each migration
func testKMSEncryptionProvidersMigration(t testing.TB) {
	ctx := context.Background()
	testClients := testlibrary.NewTestClients(t)

	// Check if KMS encryption feature gates are enabled, skip if not
	testlibrary.CheckFeatureGatesOrSkip(t, ctx, testClients.ConfigClient, features.FeatureGateKMSEncryption, features.FeatureGateKMSEncryptionProvider)

	// TODO: Remove this skip once the authentication operator fully supports KMS encryption.
	// Currently, while the API accepts encryption.type: "KMS" and the operator mounts the KMS
	// plugin socket, it does not generate the EncryptionConfiguration with KMS provider stanza.
	// This causes tests to timeout waiting for encryption keys to be created and migration to complete.
	// See: https://issues.redhat.com/browse/AUTH-XXX
	t.Skip("Skipping KMS encryption test: operator implementation is incomplete")

	librarykms.DeployUpstreamMockKMSPlugin(ctx, t, library.GetClients(t).Kube, librarykms.WellKnownUpstreamMockKMSPluginNamespace, librarykms.WellKnownUpstreamMockKMSPluginImage)
	testlibrary.TestEncryptionProvidersMigration(t, library.ProvidersMigrationScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
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
		EncryptionProviders:            library.ShuffleEncryptionProviders([]configv1.EncryptionType{configv1.EncryptionTypeKMS, library.SupportedStaticEncryptionProviders[rand.IntN(len(library.SupportedStaticEncryptionProviders))]}),
	})
}
