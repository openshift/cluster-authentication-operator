package routersecret

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func TestObserveRouterSecret(t *testing.T) {
	existingConfig := configForDomains("example.com", "supahdomain.yay")

	tests := []struct {
		name                string
		secretContent       map[string][]byte
		customSecretContent map[string][]byte
		existingConfig      map[string]interface{}
		expectedConfig      map[string]interface{}
		expectedErrs        []error
		ingressConfig       *configv1.Ingress
		expectedUpdateEvent bool
	}{
		{
			name:           "NoSecret",
			secretContent:  nil,
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
			expectedErrs:   []error{errors.NewNotFound(schema.GroupResource{Group: "", Resource: "secret"}, "v4-0-config-system-router-certs")},
		},
		{
			name: "SameConfig",
			secretContent: map[string][]byte{
				"example.com":     []byte("somecertandkey"),
				"supahdomain.yay": []byte("somecertandkey"),
			},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
		},
		{
			name: "SingleDomainCertKey",
			secretContent: map[string][]byte{
				"apps.world.com": []byte("somecertandkey"),
			},
			existingConfig:      existingConfig,
			expectedConfig:      configForDomains("apps.world.com"),
			expectedErrs:        []error{},
			expectedUpdateEvent: true,
		},
		{
			name: "MultipleDomains",
			secretContent: map[string][]byte{
				"newdomain.com":            []byte("secretandcert"),
				"newdomaindvojka.cz":       []byte("secretandcert"),
				"tehdomain.some.domain.dd": []byte("secretandcert"),
			},
			existingConfig:      existingConfig,
			expectedConfig:      configForDomains("newdomain.com", "newdomaindvojka.cz", "tehdomain.some.domain.dd"),
			expectedUpdateEvent: true,
		},
		{
			name:          "CustomSecretIsUsedWhenDefaultSecretIsNil",
			secretContent: nil,
			customSecretContent: map[string][]byte{
				"tls.key": []byte("private.key"),
				"tls.crt": []byte("certificate.crt"),
			},
			ingressConfig: &configv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "openshift-authentication",
							Name:      "oauth-openshift",
							Hostname:  "customhostname.com",
						},
					},
				},
			},
			existingConfig: existingConfig,
			expectedConfig: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"namedCertificates": []interface{}{
						map[string]interface{}{
							"names":    []interface{}{"customhostname.com"},
							"certFile": interface{}("/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.crt"),
							"keyFile":  interface{}("/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.key"),
						},
					},
				},
			},
			expectedUpdateEvent: true,
		}, {
			name: "CustomSecretIsUsedOverDefaultSecret",
			secretContent: map[string][]byte{
				"example.com":     []byte("somecertandkey"),
				"supahdomain.yay": []byte("somecertandkey"),
			},
			customSecretContent: map[string][]byte{
				"tls.key": []byte("private.key"),
				"tls.crt": []byte("certificate.crt"),
			},
			ingressConfig: &configv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.IngressSpec{
					ComponentRoutes: []configv1.ComponentRouteSpec{
						{
							Namespace: "openshift-authentication",
							Name:      "oauth-openshift",
							Hostname:  "customhostname.com",
						},
					},
				},
			},
			existingConfig: existingConfig,
			expectedConfig: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"namedCertificates": []interface{}{
						map[string]interface{}{
							"names":    []interface{}{"customhostname.com"},
							"certFile": interface{}("/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.crt"),
							"keyFile":  interface{}("/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.key"),
						},
					},
				},
			},
			expectedUpdateEvent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.secretContent != nil {
				if err := indexer.Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-router-certs",
						Namespace: "openshift-authentication",
					},
					Data: tt.secretContent,
				}); err != nil {
					t.Fatal(err)
				}
			}

			if tt.customSecretContent != nil {
				if err := indexer.Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-custom-router-certs",
						Namespace: "openshift-authentication",
					},
					Type: corev1.SecretTypeTLS,
					Data: tt.secretContent,
				}); err != nil {
					t.Fatal(err)
				}
			}

			if tt.ingressConfig != nil {
				if err := indexer.Add(tt.ingressConfig); err != nil {
					t.Fatal(err)
				}
			}

			listers := configobservation.Listers{
				SecretsLister: corev1listers.NewSecretLister(indexer),
				IngressLister: configlistersv1.NewIngressLister(indexer),
			}

			eventRecorder := events.NewInMemoryRecorder(tt.name, clocktesting.NewFakePassiveClock(time.Now()))
			gotConfig, errs := ObserveRouterSecret(listers, eventRecorder, tt.existingConfig)
			if !reflect.DeepEqual(gotConfig, tt.expectedConfig) {
				t.Errorf("ObserveRouterSecret() gotConfig = %v, want %v", gotConfig, tt.expectedConfig)
			}

			if observedEvents := eventRecorder.Events(); tt.expectedUpdateEvent != (len(observedEvents) > 0) {
				t.Errorf("ObserveRouterSecret() expected update event: %v, but got %v", tt.expectedUpdateEvent, observedEvents)
			}

			if len(errs) != len(tt.expectedErrs) {
				t.Errorf("ObserveRouterSecret() errs = %v, want %v", errs, tt.expectedErrs)
				t.FailNow()
			}

			for i := range errs {
				if errs[i].Error() != tt.expectedErrs[i].Error() {
					t.Errorf("ObserveRouterSecret() errs = %v, want %v", errs, tt.expectedErrs)
				}
			}
		})
	}
}

func configForDomains(domains ...string) map[string]interface{} {
	namedCerts := []interface{}{}
	for _, d := range domains {
		namedCerts = append(namedCerts, map[string]interface{}{
			"names":    []interface{}{"*." + d},
			"certFile": "/var/config/system/secrets/v4-0-config-system-router-certs/" + d,
			"keyFile":  "/var/config/system/secrets/v4-0-config-system-router-certs/" + d,
		})
	}

	return map[string]interface{}{
		"servingInfo": map[string]interface{}{
			"namedCertificates": namedCerts,
		},
	}
}
