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
)

func TestTokenReviewEndpointReady(t *testing.T) {
	readyDeployment := newReadyTokenReviewDeployment()
	incompleteDeployment := readyDeployment.DeepCopy()
	incompleteDeployment.Status.UpdatedReplicas = 0
	oldDeployment := readyDeployment.DeepCopy()
	oldDeployment.Spec.Template.Spec.Containers[0].Args = nil

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		endpoints  *corev1.Endpoints
		wantReady  bool
	}{
		{name: "deployment missing", endpoints: newTokenReviewEndpoints(1)},
		{name: "deployment does not serve token-review certificate", deployment: oldDeployment, endpoints: newTokenReviewEndpoints(1)},
		{name: "deployment rollout incomplete", deployment: incompleteDeployment, endpoints: newTokenReviewEndpoints(1)},
		{name: "endpoints missing", deployment: readyDeployment},
		{name: "not enough ready endpoints", deployment: newReadyTokenReviewDeploymentWithReplicas(2), endpoints: newTokenReviewEndpoints(1)},
		{name: "endpoint ready", deployment: readyDeployment, endpoints: newTokenReviewEndpoints(1), wantReady: true},
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
