package common

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

const (
	oauthAPIServerNamespace       = "openshift-oauth-apiserver"
	oauthAPIServerDeploymentName  = "apiserver"
	tokenReviewServiceName        = "token-review"
	tokenReviewServingCertFlagKey = "--tls-sni-cert-key=/var/run/secrets/token-review-serving-cert/tls.crt,"
)

// TokenReviewEndpointReady reports whether the SNI-capable oauth-apiserver revision is fully available through the token-review Service.
func TokenReviewEndpointReady(deployments appsv1listers.DeploymentLister, endpoints corev1listers.EndpointsLister) (bool, error) {
	deployment, err := deployments.Deployments(oauthAPIServerNamespace).Get(oauthAPIServerDeploymentName)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("getting deployment %s/%s: %w", oauthAPIServerNamespace, oauthAPIServerDeploymentName, err)
	}

	if !deploymentServesTokenReview(deployment) {
		return false, nil
	}

	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *deployment.Spec.Replicas
	}
	if desiredReplicas == 0 ||
		deployment.Status.ObservedGeneration < deployment.Generation ||
		deployment.Status.Replicas != desiredReplicas ||
		deployment.Status.UpdatedReplicas != desiredReplicas ||
		deployment.Status.ReadyReplicas != desiredReplicas ||
		deployment.Status.AvailableReplicas != desiredReplicas ||
		deployment.Status.UnavailableReplicas != 0 {
		return false, nil
	}

	endpoint, err := endpoints.Endpoints(oauthAPIServerNamespace).Get(tokenReviewServiceName)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("getting endpoints %s/%s: %w", oauthAPIServerNamespace, tokenReviewServiceName, err)
	}

	readyAddresses := 0
	for _, subset := range endpoint.Subsets {
		readyAddresses += len(subset.Addresses)
	}
	return int32(readyAddresses) >= desiredReplicas, nil
}

func deploymentServesTokenReview(deployment *appsv1.Deployment) bool {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "oauth-apiserver" {
			continue
		}
		for _, arg := range container.Args {
			if strings.Contains(arg, tokenReviewServingCertFlagKey) {
				return true
			}
		}
	}
	return false
}
