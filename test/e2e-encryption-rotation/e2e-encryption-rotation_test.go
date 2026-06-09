package e2e_encryption_rotation

import (
	"testing"
)

// This test calls the shared test function which
// can be called from both standard Go tests and Ginkgo tests.
//
// This situation is temporary until we verify the new e2e-aws-operator-encryption-rotation-serial-ote job.
// Eventually all tests will be run only as part of the OTE framework.
func TestEncryptionRotation(t *testing.T) {
	testEncryptionRotation(t)
}
