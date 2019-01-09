package operator2

import (
	"fmt"
	"github.com/golang/glog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func defaultAuthentication(name, metadataConfigMapName string) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: defaultLabels(),
			Annotations: map[string]string{
				// TODO - better annotations & messaging to user about defaulting behavior
				"message": "Default Authentication created by cluster-authentication-operator",
			},
		},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeIntegratedOAuth,
		},
		Status: configv1.AuthenticationStatus{
			IntegratedOAuthMetadata: configv1.ConfigMapNameReference{
				Name: metadataConfigMapName,
			},
		},
	}

}
func (c *authOperator) fetchAuthConfig() (*configv1.Authentication, error) {
	// Fetch any existing Authentication instance
	glog.V(5).Infof("fetching authentication resource '%s'", c.configName)
	existing, err := c.authentication.Get(c.configName, metav1.GetOptions{})
	if err == nil || !apierrors.IsNotFound(err) {
		// Existing instance found, or unknown error
		return existing, err
	}

	// No existing instance found; attempt to create default
	glog.V(5).Infof("creating default authentication resource '%s': metadataConfigMap '%s'", c.configName, c.targetName)
	created, err := c.authentication.Create(defaultAuthentication(c.configName, c.targetName))
	if err == nil || !apierrors.IsAlreadyExists(err) {
		// Default successfully created, or unknown error
		return created, err
	}

	// An Authentication instance must have been created between when we
	// first checked and when we attempted to create the default.
	// Find the existing instance, returning any errors trying to fetch it
	glog.V(5).Infof("re-fetching authentication resource '%s'", c.configName)
	return c.authentication.Get(c.configName, metav1.GetOptions{})
}

func (c *authOperator) updateAuthStatus(auth *configv1.Authentication) (*configv1.Authentication, error) {
	if auth == nil {
		glog.V(5).Info("no authentication resource to update status for")
		return nil, nil
	}
	var expectedRef configv1.ConfigMapNameReference
	switch auth.Spec.Type {
	case configv1.AuthenticationTypeNone:
		expectedRef = auth.Spec.OAuthMetadata
	case configv1.AuthenticationTypeIntegratedOAuth:
		expectedRef = configv1.ConfigMapNameReference{
			Name: c.targetName,
		}
	default:
		return nil, fmt.Errorf("unknown AuthenticationType '%s'", auth.Spec.Type)
	}

	if auth.Status.IntegratedOAuthMetadata != expectedRef {
		auth.Status.IntegratedOAuthMetadata = expectedRef
		glog.V(4).Infof("updating status for authentication resource '%s' to %#v", auth.GetName(), auth.Status)
		return c.authentication.UpdateStatus(auth)
	}
	glog.V(5).Infof("authentication resource '%s' status already up to date", auth.GetName())
	return auth, nil
}
