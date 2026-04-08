package e2eencryptionkms

import (
	"testing"
)

func TestKMSEncryptionOnOff(t *testing.T) {
	testKMSEncryptionOnOff(t)
}

func TestKMSEncryptionProvidersMigration(t *testing.T) {
	testKMSEncryptionProvidersMigration(t)
}
