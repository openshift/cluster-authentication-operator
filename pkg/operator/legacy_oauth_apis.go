package operator

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	apiregistrationv1listers "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"
)

type oidcAvailabilityChecker interface {
	AuthConfig() (*configv1.Authentication, error)
	OIDCAvailable() (bool, error)
}

type legacyOAuthAPIsObserver struct {
	authConfigChecker   oidcAvailabilityChecker
	featureGateAccessor featuregates.FeatureGateAccess
	deployments         appsv1listers.DeploymentLister
	endpoints           corev1listers.EndpointsLister
	services            corev1listers.ServiceLister
	secrets             corev1listers.SecretLister
	apiServices         apiregistrationv1listers.APIServiceLister
	servicesSynced      func() bool
	apiServicesSynced   func() bool
}

func (o *legacyOAuthAPIsObserver) shouldRemove() (bool, error) {
	webhookArchitectureRequired, err := externalOIDCWebhookArchitectureRequired(o.featureGateAccessor)
	if err != nil {
		return false, err
	}
	if webhookArchitectureRequired {
		return o.shouldRemoveForWebhookArchitecture()
	}
	return o.authConfigChecker.OIDCAvailable()
}

func (o *legacyOAuthAPIsObserver) shouldRemoveForWebhookArchitecture() (bool, error) {
	authConfig, err := o.authConfigChecker.AuthConfig()
	if err != nil {
		return false, err
	}
	if authConfig.Spec.Type != configv1.AuthenticationTypeOIDC {
		return false, nil
	}

	// An unsynchronized cache cannot establish that the legacy resources are absent.
	if !o.servicesSynced() {
		return false, fmt.Errorf("Service cache has not synchronized")
	}
	if !o.apiServicesSynced() {
		return false, fmt.Errorf("APIService cache has not synchronized")
	}

	// Direct OIDC has already removed these resources, even before the webhook's auth-config is synced.
	if removed, err := o.removed(); err != nil || removed {
		return removed, err
	}

	oidcAvailable, err := o.authConfigChecker.OIDCAvailable()
	if err != nil || !oidcAvailable {
		return false, err
	}

	endpointReady, err := common.TokenReviewEndpointReady(o.deployments, o.endpoints)
	if err != nil || !endpointReady {
		return false, err
	}

	return common.WebhookTargetsTokenReview(o.services, o.secrets)
}

func (o *legacyOAuthAPIsObserver) removed() (bool, error) {
	return common.LegacyOAuthAPIsRemoved(o.services, o.apiServices)
}
