package externaloidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
)

var (
	baseCACert, baseCAPrivateKey, testCertData = func() (*x509.Certificate, crypto.Signer, string) {
		cert, key, err := generateCAKeyPair()
		if err != nil {
			panic(err)
		}
		return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}()

	baseAuthResource = *newAuthWithSpec(configv1.AuthenticationSpec{
		Type: configv1.AuthenticationTypeOIDC,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: "test-oidc-provider",
				Issuer: configv1.TokenIssuer{
					CertificateAuthority: configv1.ConfigMapNameReference{Name: "oidc-ca-bundle"},
					Audiences:            []configv1.TokenAudience{"my-test-aud", "another-aud"},
					DiscoveryURL:         "https://example.com/.well-known/openid-configuration",
				},
				OIDCClients: []configv1.OIDCClientConfig{
					{
						ComponentName:      "console",
						ComponentNamespace: "openshift-console",
						ClientID:           "console-oidc-client",
					},
					{
						ComponentName:      "kube-apiserver",
						ComponentNamespace: "openshift-kube-apiserver",
						ClientID:           "test-oidc-client",
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: configv1.UsernameClaimMapping{
						Claim:        "username",
						PrefixPolicy: configv1.Prefix,
						Prefix: &configv1.UsernamePrefix{
							PrefixString: "oidc-user:",
						},
					},
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: "groups",
						},
						Prefix: "oidc-group:",
					},
				},
				ClaimValidationRules: []configv1.TokenClaimValidationRule{
					{
						Type: configv1.TokenValidationRuleRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "username",
							RequiredValue: "test-username",
						},
					},
					{
						Type: configv1.TokenValidationRuleExpression,
						Expression: configv1.TokenExpressionRule{
							Expression: "claims.email.endsWith('@example.com')",
							Message:    "email domain must be example.com",
						},
					},
				},
				UserValidationRules: []configv1.TokenUserValidationRule{
					{
						Expression: "user.groups.exists(g, g == 'system:authenticated')",
						Message:    "user must be authenticated",
					},
				},
			},
		},
	})

	baseAuthConfig = apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       kindAuthenticationConfiguration,
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
		},
		JWT: []apiserverv1beta1.JWTAuthenticator{
			{
				Issuer: apiserverv1beta1.Issuer{
					Audiences:            []string{"my-test-aud", "another-aud"},
					CertificateAuthority: testCertData,
					AudienceMatchPolicy:  apiserverv1beta1.AudienceMatchPolicyMatchAny,
					DiscoveryURL:         ptr.To("https://example.com/.well-known/openid-configuration"),
				},
				ClaimMappings: apiserverv1beta1.ClaimMappings{
					Username: apiserverv1beta1.PrefixedClaimOrExpression{
						Claim:  "username",
						Prefix: ptr.To("oidc-user:"),
					},
					Groups: apiserverv1beta1.PrefixedClaimOrExpression{
						Claim:  "groups",
						Prefix: ptr.To("oidc-group:"),
					},
				},
				ClaimValidationRules: []apiserverv1beta1.ClaimValidationRule{
					{
						Claim:         "username",
						RequiredValue: "test-username",
					},
					{
						Expression: "claims.email.endsWith('@example.com')",
						Message:    "email domain must be example.com",
					},
				},
				UserValidationRules: []apiserverv1beta1.UserValidationRule{
					{
						Expression: "user.groups.exists(g, g == 'system:authenticated')",
						Message:    "user must be authenticated",
					},
				},
			},
		},
	}

	baseAuthConfigJSON = fmt.Sprintf(`{"kind":"%s","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"$URL","certificateAuthority":"%s","audiences":["my-test-aud","another-aud"],"audienceMatchPolicy":"MatchAny"},"claimValidationRules":[{"claim":"username","requiredValue":"test-username"},{"claim":"email","requiredValue":"test-email"},{"expression":"claims.email.endsWith('@example.com')","message":"email domain must be example.com"}],"userValidationRules":[{"expression":"user.groups.exists(g, g == 'system:authenticated')","message":"user must be authenticated"}],"claimMappings":{"username":{"claim":"username","prefix":"oidc-user:"},"groups":{"claim":"groups","prefix":"oidc-group:"},"uid":{}}}]}`, kindAuthenticationConfiguration, strings.ReplaceAll(testCertData, "\n", "\\n"))
	baseAuthConfigCM   = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetAuthConfigCMName,
			Namespace: managedNamespace,
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:    "test_oidc_controller",
					Operation:  "Apply",
					APIVersion: "v1",
					FieldsV1: &metav1.FieldsV1{
						Raw: []byte(`{"f:data":{"f:auth-config.json":{}}}`),
					},
				},
			},
		},
		Data: map[string]string{
			authConfigDataKey: baseAuthConfigJSON,
		},
	}

	baseCABundleConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": testCertData,
		},
	}

	caBundleConfigMapInvalidKey = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"invalid": testCertData,
		},
	}

	caBundleConfigMapInvalidData = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "not a cert",
		},
	}

	caBundleConfigMapNoData = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "",
		},
	}
)

func TestExternalOIDCController_sync(t *testing.T) {
	testCtx := context.Background()

	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, nil)
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	for _, tt := range []struct {
		name string

		configMapIndexer     cache.Indexer
		existingAuthConfigCM *corev1.ConfigMap
		caBundleConfigMap    *corev1.ConfigMap
		auth                 *configv1.Authentication
		cmApplyReaction      k8stesting.ReactionFunc

		expectedAuthConfigJSON string
		expectEvents           bool
		expectError            bool
		featureGates           featuregates.FeatureGate
	}{
		{
			name:        "auth resource not found",
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name: "auth type IntegratedOAuth and no auth configmap",
			auth: newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:             "auth type IntegratedOAuth delete error",
			configMapIndexer: &everFailingIndexer{},
			auth:             newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			expectError:      true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:                 "auth type IntegratedOAuth configmap deleted",
			existingAuthConfigCM: &baseAuthConfigCM,
			auth:                 newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			expectEvents:         true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth type OIDC but auth config generation fails",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              &baseAuthResource,
			configMapIndexer:  cache.Indexer(&everFailingIndexer{}),
			expectEvents:      false,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth type OIDC but apply config generation fails",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = testServer.URL
					auth.Spec.OIDCProviders[0].Issuer.CertificateAuthority = configv1.ConfigMapNameReference{}
				},
			}),
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectEvents:     false,
			expectError:      true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:                 "auth type OIDC config same as existing",
			existingAuthConfigCM: authConfigCMWithIssuerURL(&baseAuthConfigCM, testServer.URL),
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = testServer.URL
				},
			}),
			expectedAuthConfigJSON: strings.ReplaceAll(baseAuthConfigJSON, "$URL", testServer.URL),
			caBundleConfigMap:      &baseCABundleConfigMap,
			expectEvents:           false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:                 "auth type OIDC error while validating config",
			caBundleConfigMap:    &baseCABundleConfigMap,
			existingAuthConfigCM: &baseAuthConfigCM,
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.Audiences = []configv1.TokenAudience{"my-test-aud", "yet-another-aud"}
				},
			}),
			expectEvents: false,
			expectError:  true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name: "auth type OIDC error while applying config",
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("apply failed")
			},
			caBundleConfigMap:    &baseCABundleConfigMap,
			existingAuthConfigCM: &baseAuthConfigCM,
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = testServer.URL
					auth.Spec.OIDCProviders[0].Issuer.Audiences = []configv1.TokenAudience{"my-test-aud", "yet-another-aud"}
				},
			}),
			expectEvents: false,
			expectError:  true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:                 "auth type OIDC apply config",
			caBundleConfigMap:    &baseCABundleConfigMap,
			existingAuthConfigCM: authConfigCMWithIssuerURL(&baseAuthConfigCM, testServer.URL),
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = testServer.URL
					auth.Spec.OIDCProviders[0].Issuer.Audiences = []configv1.TokenAudience{"my-test-aud", "yet-another-aud"}
				},
			}),
			expectedAuthConfigJSON: func() string {
				str := strings.ReplaceAll(baseAuthConfigJSON, "$URL", testServer.URL)
				str = strings.ReplaceAll(str, "another-aud", "yet-another-aud")
				return str
			}(),
			expectEvents: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:                 "auth type OIDC with UID+Extra featureGate enabled apply config",
			caBundleConfigMap:    &baseCABundleConfigMap,
			existingAuthConfigCM: authConfigCMWithIssuerURL(&baseAuthConfigCM, testServer.URL),
			auth: authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = testServer.URL
					auth.Spec.OIDCProviders[0].Issuer.Audiences = []configv1.TokenAudience{"my-test-aud", "yet-another-aud"}

					auth.Spec.OIDCProviders[0].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
						Claim: "sub",
					}
				},
			}),
			expectedAuthConfigJSON: func() string {
				authConfig := authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
					func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
						authConfig.JWT[0].Issuer.URL = testServer.URL
						authConfig.JWT[0].Issuer.Audiences = []string{"my-test-aud", "yet-another-aud"}
						authConfig.JWT[0].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
					},
				})

				out, _ := json.Marshal(authConfig)
				return string(out)
			}(),
			expectEvents: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objects := []runtime.Object{}

			authIndexer := cache.NewIndexer(func(obj interface{}) (string, error) {
				return "cluster", nil
			}, cache.Indexers{})

			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.auth != nil {
				authIndexer.Add(tt.auth)
			}

			if tt.caBundleConfigMap != nil {
				tt.configMapIndexer.Add(&baseCABundleConfigMap)
			}

			if tt.existingAuthConfigCM != nil {
				tt.configMapIndexer.Add(tt.existingAuthConfigCM)
				objects = append(objects, tt.existingAuthConfigCM)
			}

			cs := fake.NewSimpleClientset(objects...)
			if tt.cmApplyReaction != nil {
				// fake client's Apply() is a patch under the hood
				cs.PrependReactor("patch", "configmaps", tt.cmApplyReaction)
			}

			c := externalOIDCController{
				name:            "test_oidc_controller",
				configMaps:      cs.CoreV1(),
				authLister:      configv1listers.NewAuthenticationLister(authIndexer),
				configMapLister: corev1listers.NewConfigMapLister(tt.configMapIndexer),
				featureGates:    tt.featureGates,
			}

			eventRecorder := events.NewInMemoryRecorder("externaloidc-test", clocktesting.NewFakePassiveClock(time.Now()))

			err := c.sync(testCtx, factory.NewSyncContext("externaloidc-test-context", eventRecorder))

			if tt.expectError != (err != nil) {
				t.Errorf("unexpected error; want: %v; got: %v", tt.expectError, err)
			}

			if tt.expectEvents != (len(eventRecorder.Events()) > 0) {
				t.Errorf("expected events: %v; got %v", tt.expectEvents, eventRecorder.Events())
			}

			if tt.auth == nil || err != nil {
				// stop assertions here; the ones that follow are not relevant
				return
			}

			cm, err := c.configMaps.ConfigMaps(managedNamespace).Get(testCtx, targetAuthConfigCMName, metav1.GetOptions{})
			if len(tt.expectedAuthConfigJSON) == 0 && err == nil {
				t.Errorf("expected auth configmap to be missing, but it was found")
			} else if len(tt.expectedAuthConfigJSON) > 0 && errors.IsNotFound(err) {
				t.Errorf("expected auth configmap to exist but it was not found; error = %v", err)
			}

			if len(tt.expectedAuthConfigJSON) > 0 && tt.expectedAuthConfigJSON != cm.Data[authConfigDataKey] {
				t.Errorf("got unexpected auth-config data: '%s'\nexpected: '%s'", cm.Data[authConfigDataKey], tt.expectedAuthConfigJSON)
			}
		})
	}
}

func TestExternalOIDCCOntroller_deleteAuthConfig(t *testing.T) {
	testCtx := context.TODO()
	authConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetAuthConfigCMName,
			Namespace: managedNamespace,
		},
	}

	for _, tt := range []struct {
		name              string
		existingConfigMap *corev1.ConfigMap
		configMapIndexer  cache.Indexer
		cmDeleteReaction  k8stesting.ReactionFunc
		expectError       bool
		expectEvents      bool
		expectNotPresent  bool
	}{
		{
			name:              "configmap not found",
			existingConfigMap: nil,
			expectError:       false,
			expectNotPresent:  true,
			expectEvents:      false,
		},
		{
			name:              "configmap lister error",
			existingConfigMap: &authConfigMap,
			configMapIndexer:  &everFailingIndexer{},
			expectError:       true,
			expectNotPresent:  false,
			expectEvents:      false,
		},
		{
			name:              "delete error",
			existingConfigMap: &authConfigMap,
			cmDeleteReaction: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, fmt.Errorf("delete error")
			},
			expectError:      true,
			expectEvents:     false,
			expectNotPresent: false,
		},
		{
			name:              "configmap deleted",
			existingConfigMap: &authConfigMap,
			expectError:       false,
			expectEvents:      true,
			expectNotPresent:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			objects := []runtime.Object{}
			if tt.existingConfigMap != nil {
				tt.configMapIndexer.Add(tt.existingConfigMap)
				objects = append(objects, tt.existingConfigMap)
			}

			cs := fake.NewSimpleClientset(objects...)
			if tt.cmDeleteReaction != nil {
				cs.PrependReactor("delete", "configmaps", tt.cmDeleteReaction)
			}

			c := &externalOIDCController{
				configMapLister: corev1listers.NewConfigMapLister(tt.configMapIndexer),
				configMaps:      cs.CoreV1(),
			}

			eventRecorder := events.NewInMemoryRecorder("externaloidc-test", clocktesting.NewFakePassiveClock(time.Now()))
			syncCtx := factory.NewSyncContext("externaloidc-test-context", eventRecorder)

			err := c.deleteAuthConfig(testCtx, syncCtx)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v; got %v", tt.expectError, err)
			}

			if tt.expectEvents != (len(eventRecorder.Events()) > 0) {
				t.Errorf("expected events: %v; got %v", tt.expectEvents, eventRecorder.Events())
			}

			_, err = c.configMaps.ConfigMaps(managedNamespace).Get(testCtx, targetAuthConfigCMName, metav1.GetOptions{})
			if tt.expectNotPresent != errors.IsNotFound(err) {
				t.Errorf("expected configmap to be deleted=%v; got: %v", tt.expectNotPresent, errors.IsNotFound(err))
			}
		})
	}
}

func TestExternalOIDCController_generateAuthConfig(t *testing.T) {
	for _, tt := range []struct {
		name string

		auth              configv1.Authentication
		caBundleConfigMap *corev1.ConfigMap
		configMapIndexer  cache.Indexer

		expectedAuthConfig *apiserverv1beta1.AuthenticationConfiguration
		expectError        bool
		featureGates       featuregates.FeatureGate
	}{
		{
			name:             "ca bundle configmap lister error",
			auth:             baseAuthResource,
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectError:      true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "ca bundle configmap without required key",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapInvalidKey,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "ca bundle configmap with no data",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapNoData,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config nil prefix when required",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.Prefix,
							Prefix:       nil,
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config invalid prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.UsernamePrefixPolicy("invalid-policy"),
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with nil claim in validation rule",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(copy *configv1.Authentication) {
					for i := range copy.Spec.OIDCProviders {
						if len(copy.Spec.OIDCProviders[i].ClaimValidationRules) == 0 {
							copy.Spec.OIDCProviders[i].ClaimValidationRules = make([]configv1.TokenClaimValidationRule, 0)
						}
						copy.Spec.OIDCProviders[i].ClaimValidationRules = append(
							copy.Spec.OIDCProviders[i].ClaimValidationRules,
							configv1.TokenClaimValidationRule{
								Type:          configv1.TokenValidationRuleRequiredClaim, // updated constant
								RequiredClaim: nil,
							},
						)
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithUpstreamParity},
			),
		},
		{
			name:              "valid auth config",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "https://example.com"
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name: "valid auth config with empty CA name",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.CertificateAuthority.Name = ""
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.CertificateAuthority = ""
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with default prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "email",
							PrefixPolicy: configv1.NoOpinion,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "email",
							Prefix: ptr.To(""),
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with default prefix policy and username claim email",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.NoOpinion,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To("https://example.com#"),
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with no prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.NoPrefix,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To(""),
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with username claim prefix",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.Prefix,
							Prefix: &configv1.UsernamePrefix{
								PrefixString: "oidc-user:",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To("oidc-user:"),
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with empty string for username claim",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim: "",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name:              "auth config with no uid claim or expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              baseAuthResource,
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = "sub"
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with uid claim and expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
							Claim:      "sub",
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with uid expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
							Claim:      "",
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = ""
						authConfig.JWT[i].ClaimMappings.UID.Expression = "claims.sub"
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with extra missing key",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								ValueExpression: "claims.foo",
							},
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with extra missing valueExpression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key: "foo.example.com/bar",
							},
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with valid extra mappings",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key:             "foo.example.com/bar",
								ValueExpression: "claims.bar",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = "sub"
						authConfig.JWT[i].ClaimMappings.Extra = []apiserverv1beta1.ExtraMapping{
							{
								Key:             "foo.example.com/bar",
								ValueExpression: "claims.bar",
							},
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (empty)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = ""
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name: "invalid discovery URL (http instead of https)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "http://insecure-url.com"
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
		{
			name: "claim validation rule missing required claim",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].ClaimValidationRules = append(
						auth.Spec.OIDCProviders[0].ClaimValidationRules,
						configv1.TokenClaimValidationRule{
							Type:          configv1.TokenValidationRuleRequiredClaim,
							RequiredClaim: nil,
						},
					)
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
			),
		},
		{
			name: "user validation rule invalid username prefix",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].ClaimMappings.Username = configv1.UsernameClaimMapping{
						Claim:        "username",
						PrefixPolicy: configv1.UsernamePrefixPolicy("invalid-policy"),
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
				},
			),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.caBundleConfigMap != nil {
				tt.configMapIndexer.Add(tt.caBundleConfigMap)
			}

			c := externalOIDCController{
				configMapLister: corev1listers.NewConfigMapLister(tt.configMapIndexer),
				featureGates:    tt.featureGates,
			}

			gotConfig, err := c.generateAuthConfig(tt.auth)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}

			if !equality.Semantic.DeepEqual(tt.expectedAuthConfig, gotConfig) {
				t.Errorf("unexpected config diff: %s", diff.Diff(tt.expectedAuthConfig, gotConfig))
			}
		})
	}
}

func TestExternalOIDCController_getExpectedApplyConfig(t *testing.T) {
	ac, err := getExpectedApplyConfig(baseAuthConfig)
	if err != nil {
		t.Errorf("unexpected error while getting expected apply config: %v", err)
	}

	expectedAC := corev1ac.ConfigMap(targetAuthConfigCMName, managedNamespace).
		WithData(map[string]string{
			authConfigDataKey: strings.ReplaceAll(baseAuthConfigJSON, "$URL", ""),
		})

	if !equality.Semantic.DeepEqual(ac, expectedAC) {
		t.Errorf("unexpected apply config: %v", diff.Diff(ac, expectedAC))
	}
}

func TestExternalOIDCController_getExistingApplyConfig(t *testing.T) {
	for _, tt := range []struct {
		name              string
		configMapIndexer  cache.Indexer
		existingConfigMap *corev1.ConfigMap
		expectError       bool
		expectApplyConfig bool
	}{
		{
			name:              "configmap lister fails",
			configMapIndexer:  &everFailingIndexer{},
			expectError:       true,
			expectApplyConfig: false,
		},
		{
			name:              "configmap does not exist",
			existingConfigMap: nil,
			expectError:       false,
			expectApplyConfig: false,
		},
		{
			name:              "configmap exists",
			existingConfigMap: authConfigCMWithIssuerURL(&baseAuthConfigCM, "https://old-issuer.com"),
			expectError:       false,
			expectApplyConfig: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.existingConfigMap != nil {
				tt.configMapIndexer.Add(tt.existingConfigMap)
			}

			c := externalOIDCController{
				name:            "test_oidc_controller",
				configMapLister: corev1listers.NewConfigMapLister(tt.configMapIndexer),
			}

			ac, err := c.getExistingApplyConfig()

			if tt.expectError != (err != nil) {
				t.Errorf("expected error: %v; got %v", tt.expectError, err)
			}

			if tt.expectApplyConfig != (ac != nil) {
				t.Errorf("expected apply config: %v; got: %v", tt.expectApplyConfig, (err != nil))
			}

			if tt.expectApplyConfig {
				expectedAC, err := corev1ac.ExtractConfigMap(tt.existingConfigMap, c.name)
				if err != nil {
					t.Errorf("unexpected error while extracting configmap for validation: %v", err)
				}

				if !equality.Semantic.DeepEqual(ac, expectedAC) {
					t.Errorf("unexpected apply config; want: %v; got:% v", expectedAC, ac)
				}
			}
		})
	}
}

func TestExternalOIDCController_validateAuthConfig(t *testing.T) {
	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, nil)
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	for _, tt := range []struct {
		name        string
		authConfig  apiserverv1beta1.AuthenticationConfiguration
		expectError bool
	}{
		{
			name:        "empty config",
			authConfig:  apiserverv1beta1.AuthenticationConfiguration{},
			expectError: false,
		},
		{
			name: "issuer with empty URL",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = ""
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with http URL",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "http://insecure.com"
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with invalid CA",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.CertificateAuthority = "invalid CA"
				},
			}),
			expectError: true,
		},
		{
			name: "cel expression can not compile",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(*apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
						Expression: "#@!$&*(^)",
					}
				},
			}),
			expectError: true,
		},
		{
			name: "valid auth config",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = testServer.URL
				},
			}),
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthConfig(tt.authConfig)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}
		})
	}
}

func TestExternalOIDCController_validateCACert(t *testing.T) {
	certPool := x509.NewCertPool()
	certPool.AddCert(baseCACert)

	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, nil)
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	t.Run("nil CA cert to use system CAs", func(t *testing.T) {
		err := validateCACert(testServer.URL, nil)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("valid CA cert", func(t *testing.T) {
		err := validateCACert(testServer.URL, certPool)
		if err != nil {
			t.Errorf("got error while not expecting one: %v", err)
		}
	})

	t.Run("mismatched CA cert", func(t *testing.T) {
		anotherCACert, _, err := generateCAKeyPair()
		if err != nil {
			t.Errorf("could not generate CA keypair: %v", err)
		}
		certPool := x509.NewCertPool()
		certPool.AddCert(anotherCACert)
		err = validateCACert(testServer.URL, certPool)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("unknown URL", func(t *testing.T) {
		err = validateCACert("https://does-not-exist.com", certPool)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("nil cert pool", func(t *testing.T) {
		err := validateCACert(testServer.URL, nil)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("empty cert pool", func(t *testing.T) {
		err := validateCACert(testServer.URL, x509.NewCertPool())
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("well-known request error", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(6 * time.Second)
			w.WriteHeader(http.StatusOK)
		}

		testServer, err := createTestServer(baseCACert, baseCAPrivateKey, handlerFunc)
		if err != nil {
			t.Fatalf("could not create test server: %v", err)
		}
		defer testServer.Close()
		testServer.StartTLS()

		err = validateCACert(testServer.URL, certPool)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})

	t.Run("well-known status not 200 OK", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusFound)
		}

		testServer, err := createTestServer(baseCACert, baseCAPrivateKey, handlerFunc)
		if err != nil {
			t.Fatalf("could not create test server: %v", err)
		}
		defer testServer.Close()
		testServer.StartTLS()

		err = validateCACert(testServer.URL, certPool)
		if err == nil {
			t.Errorf("did not get an error while expecting one")
		}
	})
}

func generateCAKeyPair() (*x509.Certificate, crypto.Signer, error) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivateKey, err
}

func generateServingCert(caCert *x509.Certificate, caPrivateKey crypto.Signer) (*tls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Springfield"},
			StreetAddress: []string{"742 Evergreen Terrace"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &serverCert, nil
}

func createTestServer(caCert *x509.Certificate, caPrivateKey crypto.Signer, handlerFunc http.HandlerFunc) (*httptest.Server, error) {
	cert := caCert
	key := caPrivateKey
	var err error
	if caCert == nil {
		cert, key, err = generateCAKeyPair()
		if err != nil {
			return nil, err
		}
	}

	servingCertPair, err := generateServingCert(cert, key)
	if err != nil {
		return nil, err
	}

	if handlerFunc == nil {
		handlerFunc = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	testServer := httptest.NewUnstartedServer(handlerFunc)
	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*servingCertPair},
	}

	return testServer, nil
}

func makeClosedChannel() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func newAuthWithSpec(spec configv1.AuthenticationSpec) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: spec,
	}
}

func authWithUpdates(auth configv1.Authentication, updateFuncs []func(auth *configv1.Authentication)) *configv1.Authentication {
	copy := auth.DeepCopy()
	for _, updateFunc := range updateFuncs {
		updateFunc(copy)
	}
	return copy
}

func authConfigWithUpdates(authConfig apiserverv1beta1.AuthenticationConfiguration, updateFuncs []func(authConfig *apiserverv1beta1.AuthenticationConfiguration)) *apiserverv1beta1.AuthenticationConfiguration {
	copy := authConfig.DeepCopy()
	for _, updateFunc := range updateFuncs {
		updateFunc(copy)
	}
	return copy
}

func authConfigCMWithIssuerURL(cm *corev1.ConfigMap, issuerURL string) *corev1.ConfigMap {
	copy := cm.DeepCopy()
	copy.Data[authConfigDataKey] = strings.ReplaceAll(baseAuthConfigJSON, "$URL", issuerURL)
	return copy
}

type everFailingIndexer struct{}

// Index always returns an error
func (i *everFailingIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return nil, fmt.Errorf("Index method not implemented")
}

// IndexKeys always returns an error
func (i *everFailingIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, fmt.Errorf("IndexKeys method not implemented")
}

// ListIndexFuncValues always returns an error
func (i *everFailingIndexer) ListIndexFuncValues(indexName string) []string {
	return nil
}

// ByIndex always returns an error
func (i *everFailingIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	return nil, fmt.Errorf("ByIndex method not implemented")
}

// GetIndexers always returns an error
func (i *everFailingIndexer) GetIndexers() cache.Indexers {
	return nil
}

// AddIndexers always returns an error
func (i *everFailingIndexer) AddIndexers(newIndexers cache.Indexers) error {
	return fmt.Errorf("AddIndexers method not implemented")
}

// Add always returns an error
func (s *everFailingIndexer) Add(obj interface{}) error {
	return fmt.Errorf("Add method not implemented")
}

// Update always returns an error
func (s *everFailingIndexer) Update(obj interface{}) error {
	return fmt.Errorf("Update method not implemented")
}

// Delete always returns an error
func (s *everFailingIndexer) Delete(obj interface{}) error {
	return fmt.Errorf("Delete method not implemented")
}

// List always returns nil
func (s *everFailingIndexer) List() []interface{} {
	return nil
}

// ListKeys always returns nil
func (s *everFailingIndexer) ListKeys() []string {
	return nil
}

// Get always returns an error
func (s *everFailingIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("Get method not implemented")
}

// GetByKey always returns an error
func (s *everFailingIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("GetByKey method not implemented")
}

// Replace always returns an error
func (s *everFailingIndexer) Replace(objects []interface{}, sKey string) error {
	return fmt.Errorf("Replace method not implemented")
}

// Resync always returns an error
func (s *everFailingIndexer) Resync() error {
	return fmt.Errorf("Resync method not implemented")
}
