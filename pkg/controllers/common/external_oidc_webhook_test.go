package common

import (
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationv1listers "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"
)

func TestTokenReviewEndpointReady(t *testing.T) {
	readyDeployment := newReadyTokenReviewDeployment()
	incompleteDeployment := readyDeployment.DeepCopy()
	incompleteDeployment.Status.UpdatedReplicas = 0
	oldDeployment := readyDeployment.DeepCopy()
	oldDeployment.Spec.Template.Spec.Containers[0].Args = nil
	externalOIDCDeployment := readyDeployment.DeepCopy()
	externalOIDCDeployment.Spec.Template.Spec.Containers[0].Args = []string{tokenReviewTLSCertFlag, tokenReviewTLSKeyFlag}
	incompleteExternalOIDCDeployment := readyDeployment.DeepCopy()
	incompleteExternalOIDCDeployment.Spec.Template.Spec.Containers[0].Args = []string{tokenReviewTLSCertFlag}

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		endpoints  *corev1.Endpoints
		wantReady  bool
	}{
		{name: "deployment missing", endpoints: newTokenReviewEndpoints(1)},
		{name: "deployment does not serve token-review certificate", deployment: oldDeployment, endpoints: newTokenReviewEndpoints(1)},
		{name: "deployment has only primary certificate flag", deployment: incompleteExternalOIDCDeployment, endpoints: newTokenReviewEndpoints(1)},
		{name: "deployment rollout incomplete", deployment: incompleteDeployment, endpoints: newTokenReviewEndpoints(1)},
		{name: "endpoints missing", deployment: readyDeployment},
		{name: "not enough ready endpoints", deployment: newReadyTokenReviewDeploymentWithReplicas(2), endpoints: newTokenReviewEndpoints(1)},
		{name: "SNI endpoint ready", deployment: readyDeployment, endpoints: newTokenReviewEndpoints(1), wantReady: true},
		{name: "primary certificate endpoint ready", deployment: externalOIDCDeployment, endpoints: newTokenReviewEndpoints(1), wantReady: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deploymentIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			endpointsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.deployment != nil {
				if err := deploymentIndexer.Add(tt.deployment); err != nil {
					t.Fatal(err)
				}
			}
			if tt.endpoints != nil {
				if err := endpointsIndexer.Add(tt.endpoints); err != nil {
					t.Fatal(err)
				}
			}

			ready, err := TokenReviewEndpointReady(
				appsv1listers.NewDeploymentLister(deploymentIndexer),
				corev1listers.NewEndpointsLister(endpointsIndexer),
			)
			if err != nil {
				t.Fatalf("TokenReviewEndpointReady() error = %v", err)
			}
			if ready != tt.wantReady {
				t.Errorf("TokenReviewEndpointReady() = %v, want %v", ready, tt.wantReady)
			}
		})
	}
}

func TestWebhookTargetsTokenReview(t *testing.T) {
	tokenReviewService := newTokenReviewService()
	expectedServer := fmt.Sprintf("https://%s:443%s", tokenReviewService.Spec.ClusterIP, tokenReviewPath)
	malformedSecret := newWebhookSecret(expectedServer, tokenReviewServiceTLSName)
	malformedSecret.Data["kubeConfig"] = []byte("not kubeconfig")

	tests := []struct {
		name       string
		service    *corev1.Service
		secret     *corev1.Secret
		wantTarget bool
	}{
		{name: "service missing", secret: newWebhookSecret(expectedServer, tokenReviewServiceTLSName)},
		{name: "secret missing", service: tokenReviewService},
		{name: "kubeconfig malformed", service: tokenReviewService, secret: malformedSecret},
		{name: "server does not target service", service: tokenReviewService, secret: newWebhookSecret("https://10.0.0.2:443"+tokenReviewPath, tokenReviewServiceTLSName)},
		{name: "TLS name does not target service", service: tokenReviewService, secret: newWebhookSecret(expectedServer, "api.openshift-oauth-apiserver.svc")},
		{name: "targets token-review", service: tokenReviewService, secret: newWebhookSecret(expectedServer, tokenReviewServiceTLSName), wantTarget: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.service != nil {
				if err := serviceIndexer.Add(tt.service); err != nil {
					t.Fatal(err)
				}
			}
			if tt.secret != nil {
				if err := secretIndexer.Add(tt.secret); err != nil {
					t.Fatal(err)
				}
			}

			targetsTokenReview, err := WebhookTargetsTokenReview(
				corev1listers.NewServiceLister(serviceIndexer),
				corev1listers.NewSecretLister(secretIndexer),
			)
			if err != nil {
				t.Fatalf("WebhookTargetsTokenReview() error = %v", err)
			}
			if targetsTokenReview != tt.wantTarget {
				t.Errorf("WebhookTargetsTokenReview() = %v, want %v", targetsTokenReview, tt.wantTarget)
			}
		})
	}
}

func TestLegacyOAuthAPIsRemoved(t *testing.T) {
	tests := []struct {
		name        string
		service     *corev1.Service
		apiServices []*apiregistrationv1.APIService
		wantRemoved bool
	}{
		{name: "all removed", wantRemoved: true},
		{name: "api Service remains", service: &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: oauthAPIServerServiceName, Namespace: oauthAPIServerNamespace}}},
		{name: "OAuth APIService remains", apiServices: []*apiregistrationv1.APIService{{ObjectMeta: metav1.ObjectMeta{Name: oauthAPIServiceNames[0]}}}},
		{name: "User APIService remains", apiServices: []*apiregistrationv1.APIService{{ObjectMeta: metav1.ObjectMeta{Name: oauthAPIServiceNames[1]}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			apiServiceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.service != nil {
				if err := serviceIndexer.Add(tt.service); err != nil {
					t.Fatal(err)
				}
			}
			for _, apiService := range tt.apiServices {
				if err := apiServiceIndexer.Add(apiService); err != nil {
					t.Fatal(err)
				}
			}

			removed, err := LegacyOAuthAPIsRemoved(
				corev1listers.NewServiceLister(serviceIndexer),
				apiregistrationv1listers.NewAPIServiceLister(apiServiceIndexer),
			)
			if err != nil {
				t.Fatalf("LegacyOAuthAPIsRemoved() error = %v", err)
			}
			if removed != tt.wantRemoved {
				t.Errorf("LegacyOAuthAPIsRemoved() = %v, want %v", removed, tt.wantRemoved)
			}
		})
	}
}

func newReadyTokenReviewDeployment() *appsv1.Deployment {
	return newReadyTokenReviewDeploymentWithReplicas(1)
}

func newReadyTokenReviewDeploymentWithReplicas(replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: oauthAPIServerDeploymentName, Namespace: oauthAPIServerNamespace, Generation: 1},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "oauth-apiserver",
				Args: []string{tokenReviewServingCertFlagKey + "/var/run/secrets/token-review-serving-cert/tls.key"},
			}}}},
		},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			Replicas:           replicas,
			UpdatedReplicas:    replicas,
			ReadyReplicas:      replicas,
			AvailableReplicas:  replicas,
		},
	}
}

func newTokenReviewEndpoints(addresses int) *corev1.Endpoints {
	readyAddresses := make([]corev1.EndpointAddress, addresses)
	for i := range readyAddresses {
		readyAddresses[i].IP = fmt.Sprintf("10.0.1.%d", i+1)
	}
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: tokenReviewServiceName, Namespace: oauthAPIServerNamespace},
		Subsets:    []corev1.EndpointSubset{{Addresses: readyAddresses}},
	}
}

func newTokenReviewService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: tokenReviewServiceName, Namespace: oauthAPIServerNamespace},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Ports:     []corev1.ServicePort{{Port: 443}},
		},
	}
}

func newWebhookSecret(server, tlsServerName string) *corev1.Secret {
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: %s
    tls-server-name: %s
contexts:
- name: local-context
  context:
    cluster: cluster
current-context: local-context
`, server, tlsServerName)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: webhookSecretName, Namespace: webhookSecretNamespace},
		Data:       map[string][]byte{"kubeConfig": []byte(kubeconfig)},
	}
}
