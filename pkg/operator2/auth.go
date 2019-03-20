package operator2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

// FIXME: we need to handle Authentication config object properly, namely:
// - honor Type field being set to none and don't create the OSIN
//   deployment in that case
// - the OAuthMetadata settings should be better respected in the code,
//   currently there is no special handling around it (see configmap.go).
// - the WebhookTokenAuthenticators field is currently not being handled
//   anywhere
//
// Note that the configMap from the reference in the OAuthMetadata field is
// used to fill the data in the /.well-known/oauth-authorization-server
// endpoint, but since that endpoint belongs to the apiserver, its syncing is
// handled in cluster-kube-apiserver-operator
func (c *authOperator) handleAuthConfig() (*configv1.Authentication, error) {
	auth, err := c.authentication.Get(globalConfigName, metav1.GetOptions{})
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
