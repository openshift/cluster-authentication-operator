package infrastructure

import (
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func TestObserveAPIServerURL(t *testing.T) {
	existingConfig := configWithAPIServerURL("https://teh.infra.my")

	tests := []struct {
		name                string
		infraConfig         *configv1.InfrastructureStatus
		existingConfig      map[string]interface{}
		expectedConfig      map[string]interface{}
		expectedErrs        []string
		expectedUpdateEvent bool
	}{
		{
			name:           "NoInfrastructureConfig",
			infraConfig:    nil,
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
			expectedErrs:   []string{"\"cluster\" not found"},
		},
		{
			name:           "SameConfig",
			infraConfig:    &configv1.InfrastructureStatus{APIServerURL: "https://teh.infra.my"},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
		},
		{
			name:                "UpdatedInfrastructureConfig",
			infraConfig:         &configv1.InfrastructureStatus{APIServerURL: "https://my-new.api.url"},
			existingConfig:      existingConfig,
			expectedConfig:      configWithAPIServerURL("https://my-new.api.url"),
			expectedUpdateEvent: true,
		},
		{
			name:           "UnparsableAPIServerURL",
			infraConfig:    &configv1.InfrastructureStatus{APIServerURL: "https://my-new.api.url:port"},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
			expectedErrs: []string{
				"failed to parse apiServerURL \"https://my-new.api.url:port\":",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.infraConfig != nil {
				if err := indexer.Add(&configv1.Infrastructure{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Status: *tt.infraConfig,
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := configobservation.Listers{
				InfrastructureLister: configlistersv1.NewInfrastructureLister(indexer),
			}

			eventRecorder := events.NewInMemoryRecorder(tt.name, clocktesting.NewFakePassiveClock(time.Now()))
			gotConfig, errs := ObserveAPIServerURL(listers, eventRecorder, tt.existingConfig)
			if !reflect.DeepEqual(gotConfig, tt.expectedConfig) {
				t.Errorf("ObserveAPIServerURL() gotConfig = %v, want %v", gotConfig, tt.expectedConfig)
			}

			if observedEvents := eventRecorder.Events(); tt.expectedUpdateEvent != (len(observedEvents) > 0) {
				t.Errorf("ObserveRouterSecret() expected update event: %v, but got %v", tt.expectedUpdateEvent, observedEvents)
			}

			if len(errs) != len(tt.expectedErrs) {
				t.Errorf("ObserveAPIServerURL() errs = %v, want %v", errs, tt.expectedErrs)
			}

			for i := range errs {
				if strings.Contains(tt.expectedErrs[i], errs[i].Error()) {
					t.Errorf("ObserveAPIServerURL() errs = %v, want %v", errs, tt.expectedErrs)
				}
			}
		})
	}
}

func configWithAPIServerURL(url string) map[string]interface{} {
	return map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"loginURL": url,
		},
	}
}
