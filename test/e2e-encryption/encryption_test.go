package e2eencryption

import (
	"testing"
)

func TestEncryptionTypeIdentity(t *testing.T) {
	testEncryptionTypeIdentity(t)
}

func TestEncryptionTypeUnset(t *testing.T) {
	testEncryptionTypeUnset(t)
}

func TestEncryptionTurnOnAndOff(t *testing.T) {
	testEncryptionTurnOnAndOff(t)
}
