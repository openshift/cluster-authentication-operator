package routersecret

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestObserveRouterSecret(t *testing.T) {
	existingConfig := configForDomains("example.com", "supahdomain.yay")

	tests := []struct {
		name                string
		secretContent       map[string][]byte
		existingConfig      map[string]interface{}
		expectedConfig      map[string]interface{}
		expectedErrs        []error
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
			listers := configobservation.Listers{
				SecretsLister: corev1listers.NewSecretLister(indexer),
			}

			eventRecorder := events.NewInMemoryRecorder(tt.name)
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
