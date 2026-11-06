package operator

import (
	"fmt"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
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
	type testCase struct {
		name                string
		authenticationType  configv1.AuthenticationType
		oidcAvailable       bool
		legacyPresent       bool
		wantRemove          bool
		servicesUnsynced    bool
		apiServicesUnsynced bool
		wantError           string
		nodeStatuses        []operatorv1.NodeStatus
		kasConfigs          map[int32]string
		kasWebhooks         map[int32]string
		unsyncedKASCache    string
		kasAbsent           bool
		apiServiceOnly      bool
		legacyIP            string
		tokenReviewIP       string
		tokenReviewAbsent   bool
		tokenReviewNoPort   bool
	}
	const directOIDC = `{"apiServerArguments":{"authentication-config":["/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"]},"oauthMetadataFile":""}`
	const usesWebhook = `{"apiServerArguments":{"authentication-token-webhook-config-file":["/etc/kubernetes/static-pod-resources/secrets/webhook-authenticator/kubeConfig"]}}`
	tests := []testCase{
		{name: "IntegratedOAuth recreates absent legacy APIs", authenticationType: configv1.AuthenticationTypeIntegratedOAuth},
		{name: "default authentication recreates absent legacy APIs"},
		{name: "IntegratedOAuth does not wait for caches", authenticationType: configv1.AuthenticationTypeIntegratedOAuth, servicesUnsynced: true, apiServicesUnsynced: true},
		{name: "OIDC cannot infer removal before Service cache syncs", authenticationType: configv1.AuthenticationTypeOIDC, servicesUnsynced: true, wantError: "Service cache has not synchronized"},
		{name: "removal decision does not depend on APIService cache", authenticationType: configv1.AuthenticationTypeOIDC, apiServicesUnsynced: true, oidcAvailable: true, wantRemove: true},
		{name: "direct OIDC waits without recreating absent legacy APIs before auth-config is synced", authenticationType: configv1.AuthenticationTypeOIDC, kasConfigs: map[int32]string{10: directOIDC}, kasWebhooks: map[int32]string{}, tokenReviewAbsent: true, wantError: "waiting for OIDC configuration"},
		{name: "absent legacy APIs still require synchronized KAS cache", authenticationType: configv1.AuthenticationTypeOIDC, unsyncedKASCache: "KAS", wantError: "KAS cache has not synchronized"},
		{name: "absent legacy APIs still require readable revision config", authenticationType: configv1.AuthenticationTypeOIDC, kasConfigs: map[int32]string{}, wantError: "retrieving KAS config"},
		{name: "absent legacy APIs are recreated while current KAS revision still uses old endpoint", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "absent legacy APIs are recreated while target KAS revision still uses old endpoint", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}}, kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews"), 11: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "direct OIDC keeps legacy APIs removed before replacement endpoint exists", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, kasConfigs: map[int32]string{10: directOIDC}, kasWebhooks: map[int32]string{}, tokenReviewAbsent: true, wantRemove: true},
		{name: "migrated KAS keeps absent legacy APIs removed", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, wantRemove: true},
		{name: "legacy APIs remain until auth-config is synced", authenticationType: configv1.AuthenticationTypeOIDC, legacyPresent: true, wantError: "waiting for OIDC configuration"},
		{name: "migrated KAS permits removal without deployment endpoints or source Secret", authenticationType: configv1.AuthenticationTypeOIDC, oidcAvailable: true, legacyPresent: true, wantRemove: true},
	}

	// These cases have available OIDC configuration: the configuration consumed
	// by each current and pending KAS revision determines whether removal is safe.
	for _, tt := range []testCase{
		{name: "current KAS revision still uses api", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "later node still uses api", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10}, {CurrentRevision: 11}}, kasWebhooks: map[int32]string{
			10: legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews"),
			11: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews"),
		}},
		{name: "pending target still uses api", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}}, kasWebhooks: map[int32]string{
			10: legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews"),
			11: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews"),
		}},
		{name: "target uses token-review but current still uses api", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}}, kasWebhooks: map[int32]string{
			10: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews"),
			11: legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews"),
		}},
		{name: "different current and target revisions all use token-review", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}, {CurrentRevision: 11}}, wantRemove: true},
		{name: "target equal to current revision is accepted", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 10}}, wantRemove: true},
		{name: "direct OIDC dependency check needs neither webhook Secret nor revisioned auth-config", kasConfigs: map[int32]string{10: directOIDC}, kasWebhooks: map[int32]string{}, wantRemove: true},
		{name: "mixed direct OIDC and dedicated webhook revisions", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}}, kasConfigs: map[int32]string{10: directOIDC, 11: usesWebhook}, wantRemove: true},
		{name: "absent webhook alone does not establish direct OIDC", kasConfigs: map[int32]string{10: `{"apiServerArguments":{}}`}},
		{name: "unexpected direct OIDC config path blocks removal", kasConfigs: map[int32]string{10: `{"apiServerArguments":{"authentication-config":["/unknown/path"]}}`}},
		{name: "OAuth metadata does not affect legacy webhook dependency", kasConfigs: map[int32]string{10: strings.Replace(directOIDC, `"oauthMetadataFile":""`, `"oauthMetadataFile":"/oauth-metadata"`, 1)}, wantRemove: true},
		{name: "api already absent still requires synchronized KAS cache", apiServiceOnly: true, unsyncedKASCache: "KAS", wantError: "KAS cache has not synchronized"},
		{name: "api already absent permits remaining APIService removal after KAS migrates", apiServiceOnly: true, wantRemove: true},
		{name: "api already absent but current revision still targets its old IP", apiServiceOnly: true, kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "api recreated with new IP but current revision still targets its old IP", legacyIP: "10.0.0.3", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.2:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "unknown webhook destination blocks removal", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.99:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "wrong webhook TLS identity blocks removal", kasWebhooks: map[int32]string{10: strings.Replace(legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews"), "tls-server-name: token-review.openshift-oauth-apiserver.svc", "tls-server-name: api.openshift-oauth-apiserver.svc", 1)}},
		{name: "wrong webhook path blocks removal", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://10.0.0.1:443/wrong-path")}},
		{name: "HTTP webhook destination blocks removal", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("http://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "missing token-review Service blocks removal", tokenReviewAbsent: true},
		{name: "missing token-review Service port blocks removal", tokenReviewNoPort: true, wantError: "cannot determine token-review Service address"},
		{name: "IPv6 token-review destination is accepted", tokenReviewIP: "fd00::1", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://[fd00::1]:443/apis/oauth.openshift.io/v1/tokenreviews")}, wantRemove: true},
		{name: "IPv6 api destination is still in use", legacyIP: "fd00::2", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://[fd00::2]:443/apis/oauth.openshift.io/v1/tokenreviews")}},
		{name: "KAS cache must synchronize", unsyncedKASCache: "KAS", wantError: "KAS cache has not synchronized"},
		{name: "KAS ConfigMap cache must synchronize", unsyncedKASCache: "ConfigMap", wantError: "KAS ConfigMap cache has not synchronized"},
		{name: "KAS Secret cache must synchronize", unsyncedKASCache: "Secret", wantError: "KAS Secret cache has not synchronized"},
		{name: "missing KAS status blocks removal", kasAbsent: true, wantError: "getting KAS"},
		{name: "empty node statuses block removal", nodeStatuses: []operatorv1.NodeStatus{}, wantError: "no node statuses"},
		{name: "invalid current revision blocks removal", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 0}}, wantError: "unexpected revision number"},
		{name: "invalid target revision blocks removal", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: -1}}, wantError: "unexpected target revision number"},
		{name: "missing current revision config blocks removal", kasConfigs: map[int32]string{}, wantError: "retrieving KAS config at revision 10"},
		{name: "missing target revision config blocks removal", nodeStatuses: []operatorv1.NodeStatus{{CurrentRevision: 10, TargetRevision: 11}}, kasConfigs: map[int32]string{10: usesWebhook}, wantError: "retrieving KAS config at revision 11"},
		{name: "empty revision config blocks removal", kasConfigs: map[int32]string{10: ""}, wantError: "config.yaml in ConfigMap"},
		{name: "malformed revision config blocks removal", kasConfigs: map[int32]string{10: "apiServerArguments: ["}, wantError: "parsing ConfigMap"},
		{name: "unexpected webhook path blocks removal", kasConfigs: map[int32]string{10: `{"apiServerArguments":{"authentication-token-webhook-config-file":["/unknown/path"]}}`}},
		{name: "multiple webhook paths block removal", kasConfigs: map[int32]string{10: `{"apiServerArguments":{"authentication-token-webhook-config-file":["/etc/kubernetes/static-pod-resources/secrets/webhook-authenticator/kubeConfig","/other/path"]}}`}},
		{name: "missing revisioned webhook Secret blocks removal", kasWebhooks: map[int32]string{}, wantError: "getting secret openshift-kube-apiserver/webhook-authenticator-10"},
		{name: "malformed webhook kubeconfig blocks removal", kasWebhooks: map[int32]string{10: "clusters: ["}, wantError: "loading kubeconfig"},
		{name: "missing current context blocks removal", kasWebhooks: map[int32]string{10: "apiVersion: v1\nkind: Config\ncurrent-context: missing\n"}, wantError: "current context does not exist"},
		{name: "missing referenced cluster blocks removal", kasWebhooks: map[int32]string{10: "apiVersion: v1\nkind: Config\ncurrent-context: context\ncontexts:\n- name: context\n  context:\n    cluster: missing\n"}, wantError: "current context cluster does not exist"},
		{name: "malformed server URL blocks removal", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("https://[invalid")}},
		{name: "hostless server URL blocks removal", kasWebhooks: map[int32]string{10: legacyOAuthTestKubeconfig("/relative/path")}},
	} {
		tt.authenticationType = configv1.AuthenticationTypeOIDC
		tt.oidcAvailable = true
		tt.legacyPresent = true
		tests = append(tests, tt)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			apiServiceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			kasIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			kasConfigIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			kasSecretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

			tokenReviewIP := tt.tokenReviewIP
			if tokenReviewIP == "" {
				tokenReviewIP = "10.0.0.1"
			}
			tokenReviewService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "token-review", Namespace: "openshift-oauth-apiserver"},
				Spec: corev1.ServiceSpec{
					ClusterIP: tokenReviewIP,
					Ports:     []corev1.ServicePort{{Port: 443}},
				},
			}
			if tt.tokenReviewNoPort {
				tokenReviewService.Spec.Ports = nil
			}
			if !tt.tokenReviewAbsent {
				if err := serviceIndexer.Add(tokenReviewService); err != nil {
					t.Fatal(err)
				}
			}

			if tt.legacyPresent {
				if err := apiServiceIndexer.Add(&apiregistrationv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v1.oauth.openshift.io"}}); err != nil {
					t.Fatal(err)
				}
				if !tt.apiServiceOnly {
					ip := tt.legacyIP
					if ip == "" {
						ip = "10.0.0.2"
					}
					if err := serviceIndexer.Add(&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "openshift-oauth-apiserver"},
						Spec:       corev1.ServiceSpec{ClusterIP: ip, Ports: []corev1.ServicePort{{Port: 443}}},
					}); err != nil {
						t.Fatal(err)
					}
				}
			}

			statuses := tt.nodeStatuses
			if statuses == nil {
				statuses = []operatorv1.NodeStatus{{CurrentRevision: 10}}
			}
			if !tt.kasAbsent {
				if err := kasIndexer.Add(&operatorv1.KubeAPIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Status:     operatorv1.KubeAPIServerStatus{StaticPodOperatorStatus: operatorv1.StaticPodOperatorStatus{NodeStatuses: statuses}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			configs := tt.kasConfigs
			if configs == nil {
				configs = map[int32]string{10: usesWebhook, 11: usesWebhook}
			}
			for revision, config := range configs {
				if err := kasConfigIndexer.Add(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("config-%d", revision), Namespace: kasNamespace},
					Data:       map[string]string{"config.yaml": config},
				}); err != nil {
					t.Fatal(err)
				}
			}
			webhooks := tt.kasWebhooks
			if webhooks == nil {
				config := legacyOAuthTestKubeconfig("https://10.0.0.1:443/apis/oauth.openshift.io/v1/tokenreviews")
				webhooks = map[int32]string{10: config, 11: config}
			}
			for revision, config := range webhooks {
				if err := kasSecretIndexer.Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", webhookSecretName, revision), Namespace: kasNamespace},
					Data:       map[string][]byte{"kubeConfig": []byte(config)},
				}); err != nil {
					t.Fatal(err)
				}
			}
			observer := newLegacyOAuthAPIsObserver(
				fakeOIDCAvailabilityChecker{authenticationType: tt.authenticationType, oidcAvailable: tt.oidcAvailable},
				nil,
				test.NewFakeSharedIndexInformerWithSync(corev1listers.NewServiceLister(serviceIndexer), !tt.servicesUnsynced),
				test.NewFakeSharedIndexInformerWithSync(operatorv1listers.NewKubeAPIServerLister(kasIndexer), tt.unsyncedKASCache != "KAS"),
				test.NewFakeSharedIndexInformerWithSync(corev1listers.NewSecretLister(kasSecretIndexer), tt.unsyncedKASCache != "Secret"),
				test.NewFakeSharedIndexInformerWithSync(corev1listers.NewConfigMapLister(kasConfigIndexer), tt.unsyncedKASCache != "ConfigMap"),
				test.NewFakeSharedIndexInformerWithSync(apiregistrationv1listers.NewAPIServiceLister(apiServiceIndexer), !tt.apiServicesUnsynced),
			)

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

func legacyOAuthTestKubeconfig(server string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: %q
    tls-server-name: token-review.openshift-oauth-apiserver.svc
contexts:
- name: local-context
  context:
    cluster: cluster
current-context: local-context
`, server)
}

func TestLegacyOAuthAPIsObserverRemoved(t *testing.T) {
	tests := []struct {
		name              string
		servicesSynced    bool
		apiServicesSynced bool
		wantError         string
	}{
		{name: "Service cache must synchronize", wantError: "Service cache has not synchronized"},
		{name: "APIService cache must synchronize", servicesSynced: true, wantError: "APIService cache has not synchronized"},
		{name: "synchronized caches confirm absence", servicesSynced: true, apiServicesSynced: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observer := &legacyOAuthAPIsObserver{
				services:    test.NewFakeSharedIndexInformerWithSync(corev1listers.NewServiceLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})), tt.servicesSynced),
				apiServices: test.NewFakeSharedIndexInformerWithSync(apiregistrationv1listers.NewAPIServiceLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})), tt.apiServicesSynced),
			}
			removed, err := observer.removed()
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) || removed {
					t.Fatalf("removed() = (%v, %v), want (false, %q)", removed, err, tt.wantError)
				}
				return
			}
			if err != nil || !removed {
				t.Fatalf("removed() = (%v, %v), want (true, nil)", removed, err)
			}
		})
	}
}
