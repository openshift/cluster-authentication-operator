package operator2

import (
	"strconv"
	"testing"

	"k8s.io/api/core/v1"
)

func TestRandomString(t *testing.T) {
	for size := 0; size < 1<<10+1; size++ {
		size := size // capture range variable
		t.Run(strconv.FormatInt(int64(size), 10), func(t *testing.T) {
			t.Parallel()
			if got := randomString(size); len(got) != size {
				t.Errorf("randomString() -> len=%v, want len=%v, diff=%v", len(got), size, len(got)-size)
			}
		})
	}
}

func TestIsValidSessionSecret(t *testing.T) {
	s, err := newSessionSecretsJSON()
	if err != nil {
		t.Errorf("error generating new session secret")
	}
	okSecret := secret(s)
	badSecret1 := secret([]byte("thisisnotgood"))
	badSecret2 := secret([]byte(""))
	badSecrets := []*v1.Secret{badSecret1, badSecret2}
	if !isValidSessionSecret(okSecret) {
		t.Errorf("okSecret should have been valid: %v", okSecret)
	}
	for _, bs := range badSecrets {
		if isValidSessionSecret(bs) {
			t.Errorf("badSecret should not have been valid: %v", bs)
		}
	}
}

func secret(sessionSecret []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: defaultMeta(),
		Data: map[string][]byte{
			sessionNameAndKey: sessionSecret,
		},
	}
}
