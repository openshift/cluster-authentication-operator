package operator2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	legacyconfigv1 "github.com/openshift/api/legacyconfig/v1"
)

func (c *authOperator) expectedSessionSecret() (*v1.Secret, error) {
	secret, err := c.secrets.Secrets(targetName).Get(sessionNameAndKey, metav1.GetOptions{})
	if err != nil || !isValidSessionSecret(secret) {
		glog.V(4).Infof("failed to get secret %s: %v", sessionNameAndKey, err)
		generatedSessionSecret, err := randomSessionSecret()
		if err != nil {
			return nil, err
		}
		return generatedSessionSecret, nil
	}
	return secret, nil
}

func isValidSessionSecret(secret *v1.Secret) bool {
	// TODO add more validation?
	var sessionSecretsBytes [][]byte
	for _, v := range secret.Data {
		sessionSecretsBytes = append(sessionSecretsBytes, v)
	}
	for _, ss := range sessionSecretsBytes {
		var sessionSecrets *legacyconfigv1.SessionSecrets
		err := json.Unmarshal(ss, &sessionSecrets)
		if err != nil {
			return false
		}
		for _, s := range sessionSecrets.Secrets {
			if len(s.Authentication) != 64 {
				return false
			}

			if len(s.Encryption) != 32 {
				return false
			}
		}
	}
	return true
}

func randomSessionSecret() (*v1.Secret, error) {
	skey, err := newSessionSecretsJSON()
	if err != nil {
		return nil, err
	}
	meta := defaultMeta()
	meta.Name = sessionNameAndKey
	return &v1.Secret{
		ObjectMeta: meta,
		Data: map[string][]byte{
			sessionNameAndKey: skey,
		},
	}, nil
}

func newSessionSecretsJSON() ([]byte, error) {
	const (
		sha256KeyLenBytes = sha256.BlockSize // max key size with HMAC SHA256
		aes256KeyLenBytes = 32               // max key size with AES (AES-256)
	)

	secrets := &legacyconfigv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "v1",
		},
		Secrets: []legacyconfigv1.SessionSecret{
			{
				Authentication: randomString(sha256KeyLenBytes), // 64 chars
				Encryption:     randomString(aes256KeyLenBytes), // 32 chars
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		return nil, err // should never happen
	}

	return secretsBytes, nil
}

// needs to be in lib-go
func randomBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

// randomString uses RawURLEncoding to ensure we do not get / characters or trailing ='s
func randomString(size int) string {
	// each byte (8 bits) gives us 4/3 base64 (6 bits) characters
	// we account for that conversion and add one to handle truncation
	b64size := base64.RawURLEncoding.DecodedLen(size) + 1
	// trim down to the original requested size since we added one above
	return base64.RawURLEncoding.EncodeToString(randomBytes(b64size))[:size]
}
