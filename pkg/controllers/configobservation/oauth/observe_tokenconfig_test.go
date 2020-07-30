package oauth

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func TestObserveTokenConfig(t *testing.T) {
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
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds":    float64(86400),
						"authorizeTokenMaxAgeSeconds": float64(300),
					},
				},
			},
			errors: []error{},
		},
		{
			name: "max age 0 still means default max age",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenMaxAgeSeconds: 0,
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds":    float64(86400),
						"authorizeTokenMaxAgeSeconds": float64(300),
					},
				},
			},
			errors: []error{},
		},
		{
			name: "max age configured to non-default value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenMaxAgeSeconds: 172800,
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds":    float64(172800),
						"authorizeTokenMaxAgeSeconds": float64(300),
					},
				},
			},
			errors: []error{},
		},
		{
			name: "max age < 0 defaults to whatever the osin default is", // this is disabled by CR admission
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenMaxAgeSeconds: -1,
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds":    float64(-1),
						"authorizeTokenMaxAgeSeconds": float64(300),
					},
				},
			},
			errors: []error{},
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
			listers := configobservation.Listers{
				OAuthLister_: configlistersv1.NewOAuthLister(indexer),
			}
			got, errs := ObserveTokenConfig(listers, events.NewInMemoryRecorder(t.Name()), tt.previouslyObservedConfig)
			if len(errs) > 0 {
				t.Errorf("Expected 0 errors, got %v.", len(errs))
			}
			if !equality.Semantic.DeepEqual(tt.expected, got) {
				t.Errorf("result does not match expected config: %s", diff.ObjectDiff(tt.expected, got))
			}
		})
	}
}
