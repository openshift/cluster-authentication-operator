package operator

import (
	"fmt"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1listers "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"
)

type fakeOIDCAvailabilityChecker struct {
	authenticationType configv1.AuthenticationType
	oidcAvailable      bool
}

func (f fakeOIDCAvailabilityChecker) AuthConfig() (*configv1.Authentication, error) {
	return &configv1.Authentication{Spec: configv1.AuthenticationSpec{Type: f.authenticationType}}, nil
}

func (f fakeOIDCAvailabilityChecker) OIDCAvailable() (bool, error) {
	return f.oidcAvailable, nil
}

func TestLegacyOAuthAPIsObserverShouldRemoveForWebhookArchitecture(t *testing.T) {
	tests := []struct {
		name                string
		authenticationType  configv1.AuthenticationType
		oidcAvailable       bool
		legacyPresent       bool
		endpointReady       bool
		webhookTargets      bool
		wantRemove          bool
		servicesUnsynced    bool
		apiServicesUnsynced bool
		wantError           string
	}{
		{name: "IntegratedOAuth recreates absent legacy APIs", authenticationType: configv1.AuthenticationTypeIntegratedOAuth},
		{name: "default authentication recreates absent legacy APIs"},
		{name: "IntegratedOAuth does not wait for caches", authenticationType: configv1.AuthenticationTypeIntegratedOAuth, servicesUnsynced: true, apiServicesUnsynced: true},
		{name: "OIDC cannot infer removal before Service cache syncs", authenticationType: configv1.AuthenticationTypeOIDC, servicesUnsynced: true, wantError: "Service cache has not synchronized"},
		{name: "OIDC cannot infer removal before APIService cache syncs", authenticationType: configv1.AuthenticationTypeOIDC, apiServicesUnsynced: true, wantError: "APIService cache has not synchronized"},
		{name: "direct OIDC keeps absent legacy APIs removed before auth-config is synced", authenticationType: configv1.AuthenticationTypeOIDC, wantRemove: true},
		{name: "legacy OIDC keeps absent legacy APIs removed", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, wantRemove: true},
		{name: "legacy APIs remain until auth-config is synced", authenticationType: configv1.AuthenticationTypeOIDC, legacyPresent: true, endpointReady: true, webhookTargets: true},
		{name: "legacy APIs remain until endpoint is ready", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, legacyPresent: true},
		{name: "legacy APIs remain until webhook targets endpoint", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, legacyPresent: true, endpointReady: true},
		{name: "legacy APIs are removed after endpoint and webhook are ready", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, legacyPresent: true, endpointReady: true, webhookTargets: true, wantRemove: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deploymentIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			endpointsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			serviceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			apiServiceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

			tokenReviewService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "token-review", Namespace: "openshift-oauth-apiserver"},
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.0.0.1",
					Ports:     []corev1.ServicePort{{Port: 443}},
				},
			}
			if err := serviceIndexer.Add(tokenReviewService); err != nil {
				t.Fatal(err)
			}

			if tt.legacyPresent {
				if err := serviceIndexer.Add(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "openshift-oauth-apiserver"}}); err != nil {
					t.Fatal(err)
				}
			}

			if tt.endpointReady {
				replicas := int32(1)
				deployment := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-oauth-apiserver", Generation: 1},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
						Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
							Name: "oauth-apiserver",
							Args: []string{"--tls-sni-cert-key=/var/run/secrets/token-review-serving-cert/tls.crt,/var/run/secrets/token-review-serving-cert/tls.key"},
						}}}},
					},
					Status: appsv1.DeploymentStatus{
						ObservedGeneration: 1,
						Replicas:           1,
						UpdatedReplicas:    1,
						ReadyReplicas:      1,
						AvailableReplicas:  1,
					},
				}
				if err := deploymentIndexer.Add(deployment); err != nil {
					t.Fatal(err)
				}
				if err := endpointsIndexer.Add(&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{Name: "token-review", Namespace: "openshift-oauth-apiserver"},
					Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.1.1"}}}},
				}); err != nil {
					t.Fatal(err)
				}
			}

			if tt.webhookTargets {
				kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://%s:443/apis/oauth.openshift.io/v1/tokenreviews
    tls-server-name: token-review.openshift-oauth-apiserver.svc
contexts:
- name: local-context
  context:
    cluster: cluster
current-context: local-context
`, tokenReviewService.Spec.ClusterIP)
				if err := secretIndexer.Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "webhook-authentication-integrated-oauth", Namespace: "openshift-config"},
					Data:       map[string][]byte{"kubeConfig": []byte(kubeconfig)},
				}); err != nil {
					t.Fatal(err)
				}
			}

			observer := &legacyOAuthAPIsObserver{
				authConfigChecker: fakeOIDCAvailabilityChecker{authenticationType: tt.authenticationType, oidcAvailable: tt.oidcAvailable},
				deployments:       appsv1listers.NewDeploymentLister(deploymentIndexer),
				endpoints:         corev1listers.NewEndpointsLister(endpointsIndexer),
				services:          corev1listers.NewServiceLister(serviceIndexer),
				secrets:           corev1listers.NewSecretLister(secretIndexer),
				apiServices:       apiregistrationv1listers.NewAPIServiceLister(apiServiceIndexer),
				servicesSynced:    func() bool { return !tt.servicesUnsynced },
				apiServicesSynced: func() bool { return !tt.apiServicesUnsynced },
			}

			got, err := observer.shouldRemoveForWebhookArchitecture()
			if tt.wantError == "" && err != nil {
				t.Fatalf("shouldRemoveForWebhookArchitecture() unexpected error = %v", err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("shouldRemoveForWebhookArchitecture() error = %v, want %q", err, tt.wantError)
			}
			if got != tt.wantRemove {
				t.Errorf("shouldRemoveForWebhookArchitecture() = %v, want %v", got, tt.wantRemove)
			}
		})
	}
}
