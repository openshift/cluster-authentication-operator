package e2e_encryption

import (
	"testing"
)

// This test calls the shared test function which
// can be called from both standard Go tests and Ginkgo tests.
//
// This situation is temporary until we verify the new e2e-aws-operator-encryption-serial-ote job.
// Eventually all tests will be run only as part of the OTE framework.
func TestEncryptionTypeIdentity(t *testing.T) {
	testEncryptionTypeIdentity(t)
}

// This test calls the shared test function which
// can be called from both standard Go tests and Ginkgo tests.
//
// This situation is temporary until we verify the new e2e-aws-operator-encryption-serial-ote job.
// Eventually all tests will be run only as part of the OTE framework.
func TestEncryptionTypeUnset(t *testing.T) {
	testEncryptionTypeUnset(t)
}

// This test calls the shared test function which
// can be called from both standard Go tests and Ginkgo tests.
//
// This situation is temporary until we verify the new e2e-aws-operator-encryption-serial-ote job.
// Eventually all tests will be run only as part of the OTE framework.
func TestEncryptionTurnOnAndOff(t *testing.T) {
	testEncryptionTurnOnAndOff(t)
}
