package operator2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	legacyconfigv1 "github.com/openshift/api/legacyconfig/v1"
)

func (c *osinOperator) expectedSessionSecret() *v1.Secret {
	secret, err := c.secrets.Secrets(targetName).Get(targetName, metav1.GetOptions{})
	if err != nil || isInvalidSessionSecret(secret) {
		glog.V(4).Infof("failed to get secret %s: %v", targetName, err)
		return randomSessionSecret()
	}
	return secret
}

func isInvalidSessionSecret(secret *v1.Secret) bool {
	// TODO add validation
	return false
}

func randomSessionSecret() *v1.Secret {
	return &v1.Secret{
		ObjectMeta: defaultMeta(),
		Data: map[string][]byte{
			sessionKey: newSessionSecretsJSON(),
		},
	}
}

func newSessionSecretsJSON() []byte {
	const (
		sha256KeyLenBits = sha256.BlockSize * 8 // max key size with HMAC SHA256
		aes256KeyLenBits = 256                  // max key size with AES (AES-256)
	)

	secrets := &legacyconfigv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "v1",
		},
		Secrets: []legacyconfigv1.SessionSecret{
			{
				Authentication: string(randomBits(sha256KeyLenBits)), // TODO these lengths are probably wrong
				Encryption:     string(randomBits(aes256KeyLenBits)),
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		panic(err) // should never happen
	}

	return secretsBytes
}

// needs to be in lib-go
func randomBits(bits int) []byte {
	size := bits / 8
	if bits%8 != 0 {
		size++
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}
