package operator2

import (
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleAuthConfig() (*configv1.Authentication, error) {
	auth, err := c.authentication.Get(globalConfigName, metav1.GetOptions{})

	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		// did not find the object, use default
		auth = defaultAuthenticationConfig()
	}

	expectedReference := configv1.ConfigMapNameReference{
		Name: targetName,
	}

	if auth.Status.IntegratedOAuthMetadata == expectedReference {
		return auth, nil
	}

	auth.Status.IntegratedOAuthMetadata = expectedReference
	return c.authentication.UpdateStatus(auth)
}

func defaultAuthenticationConfig() *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: globalConfigName,
		},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeIntegratedOAuth,
		},
	}
}
