package operator2

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	osinv1 "github.com/openshift/api/osin/v1"

	authoputil "github.com/openshift/cluster-authentication-operator/pkg/util"
)

func (c *authOperator) expectedSessionSecret() (*corev1.Secret, error) {
	secret, err := c.secrets.Secrets("openshift-authentication").Get("v4-0-config-system-session", metav1.GetOptions{})
	if err != nil || !isValidSessionSecret(secret) {
		klog.V(4).Infof("failed to get secret %s: %v", "v4-0-config-system-session", err)
		generatedSessionSecret, err := randomSessionSecret()
		if err != nil {
			return nil, err
		}
		return generatedSessionSecret, nil
	}
	return secret, nil
}

func isValidSessionSecret(secret *corev1.Secret) bool {
	// TODO add more validation?
	var sessionSecretsBytes [][]byte
	for _, v := range secret.Data {
		sessionSecretsBytes = append(sessionSecretsBytes, v)
	}
	for _, ss := range sessionSecretsBytes {
		var sessionSecrets *osinv1.SessionSecrets
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

func randomSessionSecret() (*corev1.Secret, error) {
	skey, err := newSessionSecretsJSON()
	if err != nil {
		return nil, err
	}
	meta := defaultMeta()
	meta.Name = "v4-0-config-system-session"
	return &corev1.Secret{
		ObjectMeta: meta,
		Data: map[string][]byte{
			"v4-0-config-system-session": skey,
		},
	}, nil
}

func newSessionSecretsJSON() ([]byte, error) {
	const (
		sha256KeyLenBytes = sha256.BlockSize // max key size with HMAC SHA256
		aes256KeyLenBytes = 32               // max key size with AES (AES-256)
	)

	secrets := &osinv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "v1",
		},
		Secrets: []osinv1.SessionSecret{
			{
				Authentication: authoputil.RandomString(sha256KeyLenBytes), // 64 chars
				Encryption:     authoputil.RandomString(aes256KeyLenBytes), // 32 chars
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the session secret: %v", err) // should never happen
	}

	return secretsBytes, nil
}
