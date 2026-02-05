package e2e_encryption_kms

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
	librarykms "github.com/openshift/library-go/test/library/encryption/kms"
)

// TestKMSEncryptionOnOff tests KMS encryption on/off cycle.
// This test:
// 2. Creates a test OAuth access token (TokenOfLife)
// 3. Enables KMS encryption
// 4. Verifies token is encrypted
// 5. Disables encryption (Identity)
// 6. Verifies token is NOT encrypted
// 7. Re-enables KMS encryption
// 8. Verifies token is encrypted again
// 9. Disables encryption (Identity) again
// 10. Verifies token is NOT encrypted again
// 11. Cleans up the KMS plugin
func TestKMSEncryptionOnOff(t *testing.T) {
	// Deploy the mock KMS plugin for testing.
	// NOTE: This manual deployment is only required for KMS v1. In the future,
	// the platform will manage the KMS plugins, and this code will no longer be needed.
	librarykms.DeployUpstreamMockKMSPlugin(context.Background(), t, library.GetClients(t).Kube, librarykms.WellKnownUpstreamMockKMSPluginNamespace, librarykms.WellKnownUpstreamMockKMSPluginImage)
	library.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
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
		EncryptionProvider:             configv1.EncryptionTypeKMS,
	})
}
