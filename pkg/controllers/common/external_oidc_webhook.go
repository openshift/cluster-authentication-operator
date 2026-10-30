package common

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	apiregistrationv1listers "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"
)

const (
	oauthAPIServerNamespace       = "openshift-oauth-apiserver"
	oauthAPIServerDeploymentName  = "apiserver"
	oauthAPIServerServiceName     = "api"
	tokenReviewServiceName        = "token-review"
	webhookSecretNamespace        = "openshift-config"
	webhookSecretName             = "webhook-authentication-integrated-oauth"
	tokenReviewServingCertFlagKey = "--tls-sni-cert-key=/var/run/secrets/token-review-serving-cert/tls.crt,"
	tokenReviewTLSCertFlag        = "--tls-cert-file=/var/run/secrets/token-review-serving-cert/tls.crt"
	tokenReviewTLSKeyFlag         = "--tls-private-key-file=/var/run/secrets/token-review-serving-cert/tls.key"
	tokenReviewServiceTLSName     = "token-review.openshift-oauth-apiserver.svc"
	tokenReviewPath               = "/apis/oauth.openshift.io/v1/tokenreviews"
)

var oauthAPIServiceNames = []string{"v1.oauth.openshift.io", "v1.user.openshift.io"}

// TokenReviewEndpointReady reports whether an oauth-apiserver revision serving the token-review certificate is fully available through the token-review Service.
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

// WebhookTargetsTokenReview reports whether the managed webhook kubeconfig targets the token-review Service and TLS identity.
func WebhookTargetsTokenReview(services corev1listers.ServiceLister, secrets corev1listers.SecretLister) (bool, error) {
	service, err := services.Services(oauthAPIServerNamespace).Get(tokenReviewServiceName)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("getting service %s/%s: %w", oauthAPIServerNamespace, tokenReviewServiceName, err)
	}
	if len(service.Spec.Ports) == 0 {
		return false, nil
	}

	secret, err := secrets.Secrets(webhookSecretNamespace).Get(webhookSecretName)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("getting secret %s/%s: %w", webhookSecretNamespace, webhookSecretName, err)
	}

	kubeconfig, err := clientcmd.Load(secret.Data["kubeConfig"])
	if err != nil {
		return false, nil
	}
	context, ok := kubeconfig.Contexts[kubeconfig.CurrentContext]
	if !ok {
		return false, nil
	}
	cluster, ok := kubeconfig.Clusters[context.Cluster]
	if !ok {
		return false, nil
	}

	expectedServer := "https://" + net.JoinHostPort(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port))) + tokenReviewPath
	return cluster.Server == expectedServer && cluster.TLSServerName == tokenReviewServiceTLSName, nil
}

// LegacyOAuthAPIsRemoved reports whether the api Service and its OAuth and User APIServices are absent.
func LegacyOAuthAPIsRemoved(services corev1listers.ServiceLister, apiServices apiregistrationv1listers.APIServiceLister) (bool, error) {
	if _, err := services.Services(oauthAPIServerNamespace).Get(oauthAPIServerServiceName); err == nil {
		return false, nil
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("getting service %s/%s: %w", oauthAPIServerNamespace, oauthAPIServerServiceName, err)
	}

	for _, name := range oauthAPIServiceNames {
		if _, err := apiServices.Get(name); err == nil {
			return false, nil
		} else if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("getting APIService %s: %w", name, err)
		}
	}
	return true, nil
}

func deploymentServesTokenReview(deployment *appsv1.Deployment) bool {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "oauth-apiserver" {
			continue
		}

		servesPrimaryCert := false
		servesPrimaryKey := false
		for _, arg := range container.Args {
			if strings.Contains(arg, tokenReviewServingCertFlagKey) {
				return true
			}
			servesPrimaryCert = servesPrimaryCert || strings.Contains(arg, tokenReviewTLSCertFlag)
			servesPrimaryKey = servesPrimaryKey || strings.Contains(arg, tokenReviewTLSKeyFlag)
		}
		if servesPrimaryCert && servesPrimaryKey {
			return true
		}
	}
	return false
}
