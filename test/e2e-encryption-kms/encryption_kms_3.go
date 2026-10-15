package e2e_encryption_kms

import (
	"context"
	"testing"

	g "github.com/onsi/ginkgo/v2"

	library "github.com/openshift/library-go/test/library/encryption"
	librarykms "github.com/openshift/library-go/test/library/encryption/kms"
)

var _ = g.Describe("[sig-auth] cluster-authentication-operator", func() {
	g.It("TestKMSEncryptionRotation [OCPFeatureGate:KMSEncryption][Serial][Timeout:120m][Suite:encryption-kms-3]", func(ctx context.Context) {
		testKMSEncryptionRotation(ctx, g.GinkgoTB())
	})
})

// testKMSEncryptionRotation encrypts with Vault KMS, rotates the Vault transit
// remote key, waits for each operator's remigration, verifies ciphertext changed,
// and reverts to identity.
func testKMSEncryptionRotation(ctx context.Context, t testing.TB) {
	library.TestEncryptionRotation(ctx, t, librarykms.EncryptionRotationScenarios(ctx, t)...)
}
