package console

import (
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func TestObserveConsoleURL(t *testing.T) {
	existingConfig := configWithConsoleURL("https://teh.console.my")
	noConfig := map[string]interface{}(nil)

	tests := []struct {
		name                string
		consoleConfig       *configv1.ConsoleStatus
		clusterVersion      *configv1.ClusterVersionStatus
		existingConfig      map[string]interface{}
		expectedConfig      map[string]interface{}
		expectedErrs        []string
		expectedUpdateEvent bool
	}{
		{
			name:           "NoConsoleConfigConsoleCapabilityEnabled",
			consoleConfig:  nil,
			clusterVersion: &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityConsole}}},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
			expectedErrs:   []string{"\"cluster\" not found"},
		},
		{
			name:           "NoConsoleConfigConsoleCapabilityDisabled",
			consoleConfig:  nil,
			clusterVersion: &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{}}},
			existingConfig: noConfig,
			expectedConfig: noConfig,
			expectedErrs: []string{
				"console.config.openshift.io \"cluster\" not found",
			},
		},
		{
			// even if the cap is disabled, the observer (if invoked) will take the expected action assuming it
			// can find the console config.
			// the observer should not be invoked if the console cap is disabled.
			name:           "ConsoleConfigConsoleCapabilityDisabled",
			consoleConfig:  &configv1.ConsoleStatus{ConsoleURL: "https://teh.console.my"},
			clusterVersion: &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{}}},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
		},
		{
			name:           "SameConfig",
			consoleConfig:  &configv1.ConsoleStatus{ConsoleURL: "https://teh.console.my"},
			clusterVersion: &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityConsole}}},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
		},
		{
			name:                "UpdatedConsoleConfig",
			consoleConfig:       &configv1.ConsoleStatus{ConsoleURL: "https://my-new.console.url"},
			clusterVersion:      &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityConsole}}},
			existingConfig:      existingConfig,
			expectedConfig:      configWithConsoleURL("https://my-new.console.url"),
			expectedUpdateEvent: true,
		},
		{
			name:           "UnparsableConsoleURL",
			consoleConfig:  &configv1.ConsoleStatus{ConsoleURL: "https://my-new.console.url:port"},
			clusterVersion: &configv1.ClusterVersionStatus{Capabilities: configv1.ClusterVersionCapabilitiesStatus{EnabledCapabilities: []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityConsole}}},
			existingConfig: existingConfig,
			expectedConfig: existingConfig,
			expectedErrs: []string{
				"failed to parse consoleURL \"https://my-new.console.url:port\":",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consoleIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.consoleConfig != nil {
				if err := consoleIndexer.Add(&configv1.Console{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Status: *tt.consoleConfig,
				}); err != nil {
					t.Fatal(err)
				}
			}
			clusterVersionIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.clusterVersion != nil {
				if err := clusterVersionIndexer.Add(&configv1.ClusterVersion{
					ObjectMeta: metav1.ObjectMeta{
						Name: "version",
					},
					Status: *tt.clusterVersion,
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := configobservation.Listers{
				ConsoleLister:        configlistersv1.NewConsoleLister(consoleIndexer),
				ClusterVersionLister: configlistersv1.NewClusterVersionLister(clusterVersionIndexer),
			}

			eventRecorder := events.NewInMemoryRecorder(tt.name)
			gotConfig, errs := ObserveConsoleURL(listers, eventRecorder, tt.existingConfig)
			if !reflect.DeepEqual(gotConfig, tt.expectedConfig) {
				t.Errorf("ObserveConsoleURL() gotConfig = %v, want %v", gotConfig, tt.expectedConfig)
			}

			if observedEvents := eventRecorder.Events(); tt.expectedUpdateEvent != (len(observedEvents) > 0) {
				t.Errorf("ObserveRouterSecret() expected update event: %v, but got %v", tt.expectedUpdateEvent, observedEvents)
			}

			if len(errs) != len(tt.expectedErrs) {
				t.Errorf("ObserveConsoleURL() errs = %v, want %v", errs, tt.expectedErrs)
			}

			for i := range errs {
				if !strings.Contains(errs[i].Error(), tt.expectedErrs[i]) {
					t.Errorf("ObserveConsoleURL() errs = %v, want %v", errs, tt.expectedErrs)
				}
			}
		})
	}
}

func configWithConsoleURL(url string) map[string]interface{} {
	return map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"assetPublicURL": url,
		},
	}
}
