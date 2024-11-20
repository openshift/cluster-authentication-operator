package oauth

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func TestObserveTemplates(t *testing.T) {
	tests := []struct {
		name                     string
		config                   *configv1.OAuth
		previouslyObservedConfig map[string]interface{}
		expected                 map[string]interface{}
		errors                   []error
	}{
		{
			name:                     "nil config",
			config:                   nil,
			previouslyObservedConfig: map[string]interface{}{},
			expected:                 map[string]interface{}{},
			errors:                   []error{},
		},
		{
			name: "all templates set",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{
					Templates: configv1.OAuthTemplates{
						Login:             configv1.SecretNameReference{Name: "login-template"},
						ProviderSelection: configv1.SecretNameReference{Name: "ps-template"},
						Error:             configv1.SecretNameReference{Name: "error-template"},
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"templates": map[string]interface{}{
						"error":             "/var/config/user/template/secret/v4-0-config-user-template-error/errors.html",
						"login":             "/var/config/user/template/secret/v4-0-config-user-template-login/login.html",
						"providerSelection": "/var/config/user/template/secret/v4-0-config-user-template-provider-selection/providers.html",
					},
				},
			},
			errors: []error{},
		},
		{
			name: "remove on empty templates",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.OAuthSpec{},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"templates": map[string]interface{}{
						"error":             "/var/config/user/template/secret/v4-0-config-user-template-error/errors.html",
						"login":             "/var/config/user/template/secret/v4-0-config-user-template-login/login.html",
						"providerSelection": "/var/config/user/template/secret/v4-0-config-user-template-provider-selection/providers.html",
					},
				}},
			expected: map[string]interface{}{},
			errors:   []error{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.config != nil {
				if err := indexer.Add(tt.config); err != nil {
					t.Fatal(err)
				}
			}
			syncerData := map[string]string{}
			listers := configobservation.Listers{
				OAuthLister_:    configlistersv1.NewOAuthLister(indexer),
				ConfigMapLister: corelistersv1.NewConfigMapLister(indexer),
				ResourceSync:    &mockResourceSyncer{t: t, synced: syncerData},
			}
			got, errs := ObserveTemplates(listers, events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())), tt.previouslyObservedConfig)
			if len(errs) > 0 {
				t.Errorf("Expected 0 errors, got %v.", len(errs))
			}
			if !equality.Semantic.DeepEqual(tt.expected, got) {
				t.Errorf("result does not match expected config: %s", cmp.Diff(tt.expected, got))
			}
		})
	}
}
