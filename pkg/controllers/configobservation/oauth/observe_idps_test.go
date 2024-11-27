package oauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

type mockResourceSyncer struct {
	t      *testing.T
	synced map[string]string
}

func (rs *mockResourceSyncer) SyncConfigMap(destination, source resourcesynccontroller.ResourceLocation) error {
	if (source == resourcesynccontroller.ResourceLocation{}) {
		rs.synced[fmt.Sprintf("configmap/%v.%v", destination.Name, destination.Namespace)] = "DELETE"
	} else {
		rs.synced[fmt.Sprintf("configmap/%v.%v", destination.Name, destination.Namespace)] = fmt.Sprintf("configmap/%v.%v", source.Name, source.Namespace)
	}
	return nil
}

func (rs *mockResourceSyncer) SyncSecret(destination, source resourcesynccontroller.ResourceLocation) error {
	if (source == resourcesynccontroller.ResourceLocation{}) {
		rs.synced[fmt.Sprintf("secret/%v.%v", destination.Name, destination.Namespace)] = "DELETE"
	} else {
		rs.synced[fmt.Sprintf("secret/%v.%v", destination.Name, destination.Namespace)] = fmt.Sprintf("secret/%v.%v", source.Name, source.Namespace)
	}
	return nil
}

func TestObserveIdentityProviders(t *testing.T) {
	tests := []struct {
		name                     string
		config                   *configv1.OAuth
		configConfigMaps         []*corev1.ConfigMap
		configSecrets            []*corev1.Secret
		previouslyObservedConfig map[string]interface{}
		previousSyncerData       map[string]string
		expected                 map[string]interface{}
		expectedSyncerData       map[string]string
		expectedEvents           int
		errors                   []error
	}{
		{
			name:                     "nil config",
			config:                   nil,
			previouslyObservedConfig: map[string]interface{}{},
			previousSyncerData:       map[string]string{},
			expected:                 map[string]interface{}{},
			expectedSyncerData:       map[string]string{},
			errors:                   []error{},
		},
		{
			name: "htpasswd IdP",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.OAuthSpec{
					IdentityProviders: []configv1.IdentityProvider{
						{
							Name: "some htpasswd provider",
							IdentityProviderConfig: configv1.IdentityProviderConfig{
								Type: configv1.IdentityProviderTypeHTPasswd,
								HTPasswd: &configv1.HTPasswdIdentityProvider{
									FileData: configv1.SecretNameReference{
										Name: "somesecret",
									},
								},
							},
						},
					},
				},
			},
			configSecrets: []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "somesecret",
						Namespace: "openshift-config",
					},
					Data: map[string][]byte{
						"htpasswd": []byte("something"),
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{},
			previousSyncerData:       map[string]string{},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"identityProviders": []interface{}{
						map[string]interface{}{
							"challenge":     true,
							"login":         true,
							"mappingMethod": "claim",
							"name":          "some htpasswd provider",
							"provider": map[string]interface{}{
								"apiVersion": "osin.config.openshift.io/v1",
								"file":       "/var/config/user/idp/0/secret/v4-0-config-user-idp-0-file-data/htpasswd",
								"kind":       "HTPasswdPasswordIdentityProvider",
							},
						},
					},
				},
				"volumesToMount": map[string]interface{}{
					"identityProviders": string(`{"v4-0-config-user-idp-0-file-data":{"name":"somesecret","mountPath":"/var/config/user/idp/0/secret/v4-0-config-user-idp-0-file-data","key":"htpasswd","type":"secret"}}`),
				},
			},
			expectedSyncerData: map[string]string{
				"secret/v4-0-config-user-idp-0-file-data.openshift-authentication": "secret/somesecret.openshift-config",
			},
			expectedEvents: 1,
			errors:         []error{},
		},
		{
			name: "remove an IdP",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.OAuthSpec{},
			},
			configSecrets: []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-user-idp-0-file-data",
						Namespace: "openshift-authentication",
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"identityProviders": []interface{}{
						map[string]interface{}{
							"challenge":     true,
							"login":         true,
							"mappingMethod": "claim",
							"name":          "some htpasswd provider",
							"provider": map[string]interface{}{
								"apiVersion": "osin.config.openshift.io/v1",
								"file":       "/var/config/user/idp/0/secret/v4-0-config-user-idp-0-file-data/htpasswd",
								"kind":       "HTPasswdPasswordIdentityProvider",
							},
						},
					},
				},
				"volumesToMount": map[string]interface{}{
					"identityProviders": string(`{"v4-0-config-user-idp-0-file-data":{"name":"somesecret","mountPath":"/var/config/user/idp/0/secret/v4-0-config-user-idp-0-file-data","key":"htpasswd","type":"secret"}}`),
				},
			},
			previousSyncerData: map[string]string{
				"secret/v4-0-config-user-idp-0-file-data.openshift-authentication": "secret/somesecret.openshift-config",
			},
			expected: map[string]interface{}{
				"volumesToMount": map[string]interface{}{
					"identityProviders": string(`{}`),
				},
			},
			expectedSyncerData: map[string]string{
				"secret/v4-0-config-user-idp-0-file-data.openshift-authentication": "DELETE",
			},
			expectedEvents: 1,
			errors:         []error{},
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
			for _, s := range tt.configSecrets {
				if err := indexer.Add(s); err != nil {
					t.Fatal(err)
				}
			}
			for _, cm := range tt.configConfigMaps {
				if err := indexer.Add(cm); err != nil {
					t.Fatal(err)
				}
			}

			syncerData := tt.previousSyncerData
			listers := configobservation.Listers{
				ConfigMapLister: corelistersv1.NewConfigMapLister(indexer),
				SecretsLister:   corelistersv1.NewSecretLister(indexer),
				OAuthLister_:    configlistersv1.NewOAuthLister(indexer),
				ResourceSync:    &mockResourceSyncer{t: t, synced: syncerData},
			}
			eventsRecorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))

			got, errs := ObserveIdentityProviders(listers, eventsRecorder, tt.previouslyObservedConfig)

			if len(errs) > 0 {
				t.Errorf("Expected 0 errors, got %v.", errs)
			}

			if gotEvents := eventsRecorder.Events(); tt.expectedEvents != len(gotEvents) {
				t.Errorf("Expected %d events, got %v.", tt.expectedEvents, eventsReasonMessage(gotEvents))
			}

			if !equality.Semantic.DeepEqual(tt.expected, got) {
				t.Errorf("result does not match expected config: %s", cmp.Diff(tt.expected, got))
			}
			if !equality.Semantic.DeepEqual(tt.expectedSyncerData, syncerData) {
				t.Errorf("expected syncer data:\n %#v\ngot:\n %v", tt.expectedSyncerData, syncerData)
			}
		})
	}
}

func eventsReasonMessage(e []*corev1.Event) []string {
	reasonMessages := make([]string, 0, len(e))
	for _, ev := range e {
		reasonMessages = append(reasonMessages, fmt.Sprintf("%s: %s", ev.Reason, ev.Message))
	}
	return reasonMessages
}
