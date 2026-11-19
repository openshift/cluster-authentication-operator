package common

import (
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
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
		name           string
		deployment     *appsv1.Deployment
		endpointSlices []*discoveryv1.EndpointSlice
		wantReady      bool
	}{
		{name: "deployment missing", endpointSlices: sliceList(newTokenReviewEndpointSlice(1))},
		{name: "deployment does not serve token-review certificate", deployment: oldDeployment, endpointSlices: sliceList(newTokenReviewEndpointSlice(1))},
		{name: "deployment has only primary certificate flag", deployment: incompleteExternalOIDCDeployment, endpointSlices: sliceList(newTokenReviewEndpointSlice(1))},
		{name: "deployment rollout incomplete", deployment: incompleteDeployment, endpointSlices: sliceList(newTokenReviewEndpointSlice(1))},
		{name: "endpoints missing", deployment: readyDeployment},
		{name: "not enough ready endpoints", deployment: newReadyTokenReviewDeploymentWithReplicas(2), endpointSlices: sliceList(newTokenReviewEndpointSlice(1))},
		{name: "not-ready endpoints are not counted", deployment: readyDeployment, endpointSlices: sliceList(newTokenReviewEndpointSliceNotReady(1))},
		{name: "SNI endpoint ready", deployment: readyDeployment, endpointSlices: sliceList(newTokenReviewEndpointSlice(1)), wantReady: true},
		{name: "primary certificate endpoint ready", deployment: externalOIDCDeployment, endpointSlices: sliceList(newTokenReviewEndpointSlice(1)), wantReady: true},
		{
			// Dual-stack: a single Pod appears once per IP family, so its IPv4
			// and IPv6 addresses live in separate slices but share a Pod UID.
			// Deduplication by UID must count that Pod once, leaving a
			// two-replica deployment short of its desired backends.
			name:       "dual-stack duplicate pod counted once is not enough",
			deployment: newReadyTokenReviewDeploymentWithReplicas(2),
			endpointSlices: sliceList(
				newTokenReviewEndpointSliceForPods("ipv4", discoveryv1.AddressTypeIPv4, "10.0.1.", "pod-a"),
				newTokenReviewEndpointSliceForPods("ipv6", discoveryv1.AddressTypeIPv6, "fd00::", "pod-a"),
			),
		},
		{
			// Two distinct Pods, each with an IPv4 and IPv6 address across two
			// slices. Deduplication by UID yields two ready backends, matching
			// the two desired replicas.
			name:       "dual-stack distinct pods satisfy desired replicas",
			deployment: newReadyTokenReviewDeploymentWithReplicas(2),
			endpointSlices: sliceList(
				newTokenReviewEndpointSliceForPods("ipv4", discoveryv1.AddressTypeIPv4, "10.0.1.", "pod-a", "pod-b"),
				newTokenReviewEndpointSliceForPods("ipv6", discoveryv1.AddressTypeIPv6, "fd00::", "pod-a", "pod-b"),
			),
			wantReady: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deploymentIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			endpointSliceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.deployment != nil {
				if err := deploymentIndexer.Add(tt.deployment); err != nil {
					t.Fatal(err)
				}
			}
			for _, endpointSlice := range tt.endpointSlices {
				if err := endpointSliceIndexer.Add(endpointSlice); err != nil {
					t.Fatal(err)
				}
			}

			ready, err := TokenReviewEndpointReady(
				appsv1listers.NewDeploymentLister(deploymentIndexer),
				discoveryv1listers.NewEndpointSliceLister(endpointSliceIndexer),
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

func newTokenReviewEndpointSlice(addresses int) *discoveryv1.EndpointSlice {
	return newTokenReviewEndpointSliceWithReadiness(addresses, true)
}

func newTokenReviewEndpointSliceNotReady(addresses int) *discoveryv1.EndpointSlice {
	return newTokenReviewEndpointSliceWithReadiness(addresses, false)
}

func newTokenReviewEndpointSliceWithReadiness(addresses int, ready bool) *discoveryv1.EndpointSlice {
	endpoints := make([]discoveryv1.Endpoint, addresses)
	for i := range endpoints {
		endpoints[i] = discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.0.1.%d", i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tokenReviewServiceName + "-abcde",
			Namespace: oauthAPIServerNamespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: tokenReviewServiceName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
}

// sliceList is a convenience constructor for an EndpointSlice list literal.
func sliceList(s ...*discoveryv1.EndpointSlice) []*discoveryv1.EndpointSlice {
	return s
}

// newTokenReviewEndpointSliceForPods builds a ready EndpointSlice of the given
// address family with one endpoint per Pod UID, each carrying a Pod TargetRef.
// This models a dual-stack Service where a single Pod is represented once per IP
// family across separate slices.
func newTokenReviewEndpointSliceForPods(suffix string, addressType discoveryv1.AddressType, addressPrefix string, podUIDs ...string) *discoveryv1.EndpointSlice {
	endpoints := make([]discoveryv1.Endpoint, len(podUIDs))
	for i, uid := range podUIDs {
		ready := true
		endpoints[i] = discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("%s%d", addressPrefix, i+1)},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef: &corev1.ObjectReference{
				Kind:      "Pod",
				Namespace: oauthAPIServerNamespace,
				Name:      "oauth-apiserver-" + uid,
				UID:       types.UID(uid),
			},
		}
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tokenReviewServiceName + "-" + suffix,
			Namespace: oauthAPIServerNamespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: tokenReviewServiceName},
		},
		AddressType: addressType,
		Endpoints:   endpoints,
	}
}
