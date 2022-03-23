package oauth_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
)

func TestAuditProfile(t *testing.T) {
	auditOpts := map[string]interface{}{
		"serverArguments": map[string]interface{}{
			"audit-log-format":    []interface{}{string("json")},
			"audit-log-maxbackup": []interface{}{string("10")},
			"audit-log-maxsize":   []interface{}{string("100")},
			"audit-log-path":      []interface{}{string("/var/log/oauth-server/audit.log")},
			"audit-policy-file":   []interface{}{string("/var/run/configmaps/audit/audit.yaml")},
		},
	}

	for _, tt := range [...]struct {
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
			expected:                 auditOpts,
			errors:                   []error{},
		},
		{
			name: "disable audit options from scratch",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{Audit: configv1.OAuthAudit{
					Profile: configv1.OAuthAuditProfileNone,
				}},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected:                 map[string]interface{}{},
		},
		{
			name: "enable audit options from scratch",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{Audit: configv1.OAuthAudit{
					Profile: configv1.OAuthAuditProfileWriteLoginEvents,
				}},
			},
			previouslyObservedConfig: map[string]interface{}{},
			expected:                 auditOpts,
		},
		{
			name: "disable audit profile from enabled",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{Audit: configv1.OAuthAudit{
					Profile: configv1.OAuthAuditProfileNone,
				}},
			},
			previouslyObservedConfig: auditOpts,
			expected:                 map[string]interface{}{},
		},
	} {
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

			have, errs := oauth.ObserveAudit(listers, events.NewInMemoryRecorder(t.Name()), tt.previouslyObservedConfig)
			if len(errs) > 0 {
				t.Errorf("Expected 0 errors, have %v.", len(errs))
			}

			if !equality.Semantic.DeepEqual(tt.expected, have) {
				t.Errorf("result does not match expected config: %s", cmp.Diff(tt.expected, have))
			}

		})
	}
}
