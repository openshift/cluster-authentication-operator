package library

import (
	"testing"

	localEncryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
)

// These wrapper functions provide compatibility between Ginkgo v2's testing.TB
// and library-go's test functions that expect *testing.T.
//
// Instead of using unsafe pointer conversions (which cause concurrent map access
// panics when t.Helper() is called), we use local implementations that properly
// handle testing.TB.

// TestEncryptionTypeIdentity tests encryption with identity mode.
// This calls the local implementation instead of library-go to avoid unsafe conversions.
func TestEncryptionTypeIdentity(tb testing.TB, scenario library.BasicScenario) {
	localEncryption.TestEncryptionTypeIdentity(tb, scenario)
}

// TestEncryptionTypeUnset tests encryption with unset mode.
// This calls the local implementation instead of library-go to avoid unsafe conversions.
func TestEncryptionTypeUnset(tb testing.TB, scenario library.BasicScenario) {
	localEncryption.TestEncryptionTypeUnset(tb, scenario)
}

// TestEncryptionTurnOnAndOff tests turning encryption on and off.
// This calls the local implementation instead of library-go to avoid unsafe conversions.
func TestEncryptionTurnOnAndOff(tb testing.TB, scenario library.OnOffScenario) {
	localEncryption.TestEncryptionTurnOnAndOff(tb, scenario)
}

// TestEncryptionRotation tests encryption key rotation.
// This calls the local implementation instead of library-go to avoid unsafe conversions.
func TestEncryptionRotation(tb testing.TB, scenario library.RotationScenario) {
	localEncryption.TestEncryptionRotation(tb, scenario)
}

// TestPerfEncryption tests encryption performance.
// This calls the local implementation instead of library-go to avoid unsafe conversions.
func TestPerfEncryption(tb testing.TB, scenario library.PerfScenario) {
	localEncryption.TestPerfEncryption(tb, scenario)
}
