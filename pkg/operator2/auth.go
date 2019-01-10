package operator2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *osinOperator) handleAuthConfig() (*configv1.Authentication, error) {
	auth, err := c.authentication.Get(configName, metav1.GetOptions{})
	if err != nil {
		return nil, err
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
