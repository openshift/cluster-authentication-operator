package common

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	test "github.com/openshift/cluster-authentication-operator/test/library"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	kasConfigJSONWithOIDC    = `"spec":{"apiServerArguments":{"authentication-config":["/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"]},"oauthMetadataFile":""}`
	kasConfigJSONWithoutOIDC = `"spec":{"apiServerArguments":{"authentication-token-webhook-config-file":["/etc/kubernetes/static-pod-resources/secrets/webhook-authenticator/kubeConfig"]},"oauthMetadataFile":"/etc/kubernetes/static-pod-resources/configmaps/oauth-metadata/oauthMetadata"}`
)

func TestExternalOIDCConfigAvailable(t *testing.T) {
	for _, tt := range []struct {
		name               string
		authInformerSynced bool
		kasInformerSynced  bool
		cmInformerSynced   bool
		configMaps         []*corev1.ConfigMap
		authType           configv1.AuthenticationType
		nodeStatuses       []operatorv1.NodeStatus
		expectAvailable    bool
		expectError        bool
	}{
		{
			name:               "no node statuses observed",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeOIDC,
			expectAvailable:    false,
			expectError:        true,
		},
		{
			name:               "some node revisions are zero",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 10},
				{CurrentRevision: 10},
				{CurrentRevision: 0},
			},
			expectAvailable: false,
			expectError:     true,
		},
		{
			name:               "node revisions are zero",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 0},
				{CurrentRevision: 0},
				{CurrentRevision: 0},
			},
			expectAvailable: false,
			expectError:     true,
		},
		{
			name:               "oidc disabled, no rollout",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps:         []*corev1.ConfigMap{cm("config-10", "config.yaml", kasConfigJSONWithoutOIDC)},
			authType:           configv1.AuthenticationTypeIntegratedOAuth,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 10},
				{CurrentRevision: 10},
				{CurrentRevision: 10},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc getting enabled, rollout in progress",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-10", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 10, TargetRevision: 11},
				{CurrentRevision: 10},
				{CurrentRevision: 10},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc getting enabled, rollout in progress, one node ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-10", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 11},
				{CurrentRevision: 10, TargetRevision: 11},
				{CurrentRevision: 10},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc getting enabled, rollout in progress, two nodes ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-10", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 11},
				{CurrentRevision: 11},
				{CurrentRevision: 10, TargetRevision: 11},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc got enabled",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 11},
				{CurrentRevision: 11},
				{CurrentRevision: 11},
			},
			expectAvailable: true,
			expectError:     false,
		},
		{
			name:               "oidc enabled, rollout in progress",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 11, TargetRevision: 12},
				{CurrentRevision: 11},
				{CurrentRevision: 11},
			},
			expectAvailable: true,
			expectError:     false,
		},
		{
			name:               "oidc enabled, rollout in progress, one node ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 12},
				{CurrentRevision: 11, TargetRevision: 12},
				{CurrentRevision: 11},
			},
			expectAvailable: true,
			expectError:     false,
		},
		{
			name:               "oidc enabled, rollout in progress, two nodes ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 12},
				{CurrentRevision: 12},
				{CurrentRevision: 11, TargetRevision: 12},
			},
			expectAvailable: true,
			expectError:     false,
		},
		{
			name:               "oidc still enabled",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 12},
				{CurrentRevision: 12},
				{CurrentRevision: 12},
			},
			expectAvailable: true,
			expectError:     false,
		},
		{
			name:               "oidc getting disabled, rollout in progress",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-13", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeIntegratedOAuth,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 12, TargetRevision: 13},
				{CurrentRevision: 12},
				{CurrentRevision: 12},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc getting disabled, rollout in progress, one node ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-13", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeIntegratedOAuth,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 13},
				{CurrentRevision: 12, TargetRevision: 13},
				{CurrentRevision: 12},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc getting disabled, rollout in progress, two nodes ready",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeIntegratedOAuth,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-13", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 13},
				{CurrentRevision: 13},
				{CurrentRevision: 12, TargetRevision: 13},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "oidc got disabled",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			configMaps: []*corev1.ConfigMap{
				cm("config-11", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-12", "config.yaml", kasConfigJSONWithOIDC),
				cm("config-13", "config.yaml", kasConfigJSONWithoutOIDC),
				cm("auth-config-11", "", ""),
				cm("auth-config-12", "", ""),
			},
			authType: configv1.AuthenticationTypeIntegratedOAuth,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 13},
				{CurrentRevision: 13},
				{CurrentRevision: 13},
			},
			expectAvailable: false,
			expectError:     false,
		},
		{
			name:               "auth informer not synced",
			authInformerSynced: false,
			kasInformerSynced:  true,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeOIDC,
			expectAvailable:    false,
			expectError:        true,
		},
		{
			name:               "kas informer not synced",
			authInformerSynced: true,
			kasInformerSynced:  false,
			cmInformerSynced:   true,
			authType:           configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 10},
				{CurrentRevision: 10},
				{CurrentRevision: 10},
			},
			expectAvailable: false,
			expectError:     true,
		},
		{
			name:               "configmap informer not synced",
			authInformerSynced: true,
			kasInformerSynced:  true,
			cmInformerSynced:   false,
			authType:           configv1.AuthenticationTypeOIDC,
			nodeStatuses: []operatorv1.NodeStatus{
				{CurrentRevision: 10},
				{CurrentRevision: 10},
				{CurrentRevision: 10},
			},
			expectAvailable: false,
			expectError:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {

			cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, cm := range tt.configMaps {
				cmIndexer.Add(cm)
			}

			kasIndexer := cache.NewIndexer(func(obj any) (string, error) {
				return "cluster", nil
			}, cache.Indexers{})

			kasIndexer.Add(&operatorv1.KubeAPIServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Status: operatorv1.KubeAPIServerStatus{
					StaticPodOperatorStatus: operatorv1.StaticPodOperatorStatus{
						NodeStatuses: tt.nodeStatuses,
					},
				},
			})

			authIndexer := cache.NewIndexer(func(obj any) (string, error) {
				return "cluster", nil
			}, cache.Indexers{})

			authIndexer.Add(&configv1.Authentication{
				Spec: configv1.AuthenticationSpec{
					Type: tt.authType,
				},
			})

			authConfigChecker := NewAuthConfigChecker(
				test.NewFakeSharedIndexInformerWithSync(configv1listers.NewAuthenticationLister(authIndexer), tt.authInformerSynced),
				test.NewFakeSharedIndexInformerWithSync(operatorv1listers.NewKubeAPIServerLister(kasIndexer), tt.kasInformerSynced),
				test.NewFakeSharedIndexInformerWithSync(corelistersv1.NewConfigMapLister(cmIndexer), tt.cmInformerSynced),
			)

			available, err := authConfigChecker.OIDCAvailable()

			if tt.expectError != (err != nil) {
				t.Fatalf("expected error %v; got %v", tt.expectError, err)
			}

			if tt.expectAvailable != available {
				t.Fatalf("expected available %v; got %v", tt.expectAvailable, available)
			}
		})
	}
}

func cm(name, dataKey, dataValue string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-kube-apiserver",
		},
	}

	if len(dataKey) > 0 {
		cm.Data = map[string]string{
			dataKey: dataValue,
		}
	}

	return cm
}
