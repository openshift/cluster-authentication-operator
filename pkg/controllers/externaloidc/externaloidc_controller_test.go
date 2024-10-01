package externaloidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

var (
	featureGatesWithOIDC = featuregates.NewHardcodedFeatureGateAccessForTesting(
		[]configv1.FeatureGateName{features.FeatureGateExternalOIDC},
		[]configv1.FeatureGateName{},
		makeClosedChannel(),
		nil,
	)

	testCertData = func() string {
		caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
		if err != nil {
			panic(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	}()

	baseAuthResource = *newAuthWithSpec(configv1.AuthenticationSpec{
		Type: configv1.AuthenticationTypeOIDC,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: "test-oidc-provider",
				Issuer: configv1.TokenIssuer{
					URL:                  "https://test-oidc-provider.com",
					CertificateAuthority: configv1.ConfigMapNameReference{Name: "oidc-ca-bundle"},
					Audiences:            []configv1.TokenAudience{"my-test-aud", "another-aud"},
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
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: "username",
						},
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
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "username",
							RequiredValue: "test-username",
						},
					},
					{
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "email",
							RequiredValue: "test-email",
						},
					},
				},
			},
		},
	})

	baseAuthConfig = *newAuthConfig([]apiserverv1beta1.JWTAuthenticator{
		{
			Issuer: apiserverv1beta1.Issuer{
				URL:                  "https://test-oidc-provider.com",
				Audiences:            []string{"my-test-aud", "another-aud"},
				CertificateAuthority: testCertData,
				AudienceMatchPolicy:  apiserverv1beta1.AudienceMatchPolicyMatchAny,
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
					Claim:         "email",
					RequiredValue: "test-email",
				},
			},
		},
	})

	baseAuthConfigJSON = fmt.Sprintf(`{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"https://test-oidc-provider.com","certificateAuthority":"%s","audiences":["my-test-aud","another-aud"],"audienceMatchPolicy":"MatchAny"},"claimValidationRules":[{"claim":"username","requiredValue":"test-username"},{"claim":"email","requiredValue":"test-email"}],"claimMappings":{"username":{"claim":"username","prefix":"oidc-user:"},"groups":{"claim":"groups","prefix":"oidc-group:"},"uid":{}}}]}`, strings.ReplaceAll(testCertData, "\n", "\\n"))

	baseAuthConfigCM = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetAuthConfigCMName,
			Namespace: targetConfigMapNamespace,
		},
		Data: map[string]string{
			authConfigDataKey: baseAuthConfigJSON,
		},
	}

	baseCABundleConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: caBundleConfigMapNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": testCertData,
		},
	}

	caBundleConfigMapInvalidKey = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: caBundleConfigMapNamespace,
		},
		Data: map[string]string{
			"invalid": testCertData,
		},
	}

	caBundleConfigMapInvalidData = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: caBundleConfigMapNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "not a cert",
		},
	}

	caBundleConfigMapNoData = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: caBundleConfigMapNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "",
		},
	}
)

func TestExternalOIDCController_sync(t *testing.T) {
	testCtx := context.Background()
	for _, tt := range []struct {
		name string

		featureGates         featuregates.FeatureGateAccess
		existingAuthConfigCM *corev1.ConfigMap
		caBundleConfigMap    *corev1.ConfigMap
		auth                 *configv1.Authentication
		cmApplyReaction      k8stesting.ReactionFunc
		cmDeleteReaction     k8stesting.ReactionFunc

		expectError bool
	}{
		{
			name:        "nil feature gates accessor",
			expectError: false,
		},
		{
			name: "feature gates not observed",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{},
				make(chan struct{}),
				nil,
			),
			expectError: false,
		},
		{
			name: "feature gates access error",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{},
				makeClosedChannel(),
				fmt.Errorf("access error"),
			),
			expectError: true,
		},
		{
			name: "OIDC feature gate disabled",
			featureGates: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDC},
				makeClosedChannel(),
				nil,
			),
			expectError: false,
		},
		{
			name:         "OIDC feature gate enabled but auth not found",
			featureGates: featureGatesWithOIDC,
			expectError:  true,
		},
		{
			name:                 "OIDC feature gate enabled and auth type IntegratedOAuth and failing to delete cm",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			cmDeleteReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("error")
			},
			auth:        newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			expectError: true,
		},
		{
			name:         "OIDC feature gate enabled and auth type IntegratedOAuth and no auth configmap",
			featureGates: featureGatesWithOIDC,
			auth:         newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			expectError:  false,
		},
		{
			name:                 "OIDC feature gate enabled and auth type IntegratedOAuth with auth configmap",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			caBundleConfigMap:    &baseCABundleConfigMap,
			auth:                 newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeIntegratedOAuth}),
			expectError:          false,
		},
		{
			name:                 "OIDC feature gate enabled and auth type empty and failing to delete cm",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			cmDeleteReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("error")
			},
			auth:        newAuthWithSpec(configv1.AuthenticationSpec{Type: ""}),
			expectError: true,
		},
		{
			name:              "OIDC feature gate enabled and auth type empty and no auth configmap",
			featureGates:      featureGatesWithOIDC,
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              newAuthWithSpec(configv1.AuthenticationSpec{Type: ""}),
			expectError:       false,
		},
		{
			name:                 "OIDC feature gate enabled and auth type empty with auth configmap",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			caBundleConfigMap:    &baseCABundleConfigMap,
			auth:                 newAuthWithSpec(configv1.AuthenticationSpec{Type: ""}),
			expectError:          false,
		},
		{
			name:                 "OIDC feature gate enabled and auth type None and failing to delete cm",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			cmDeleteReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("error")
			},
			auth:        newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeNone}),
			expectError: true,
		},
		{
			name:              "OIDC feature gate enabled and auth type None and no auth configmap",
			featureGates:      featureGatesWithOIDC,
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeNone}),
			expectError:       false,
		},
		{
			name:                 "OIDC feature gate enabled and auth type None with auth configmap",
			featureGates:         featureGatesWithOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			caBundleConfigMap:    &baseCABundleConfigMap,
			auth:                 newAuthWithSpec(configv1.AuthenticationSpec{Type: configv1.AuthenticationTypeNone}),
			expectError:          false,
		},
		{
			name:              "OIDC feature gate enabled and auth type invalid",
			featureGates:      featureGatesWithOIDC,
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              newAuthWithSpec(configv1.AuthenticationSpec{Type: "invalid"}),
			expectError:       true,
		},
		{
			name:              "OIDC feature gate enabled and auth type OIDC",
			featureGates:      featureGatesWithOIDC,
			caBundleConfigMap: &baseCABundleConfigMap,
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, &baseAuthConfigCM, nil
			},
			auth:        &baseAuthResource,
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authIndexer := cache.NewIndexer(func(obj interface{}) (string, error) {
				return "cluster", nil
			}, cache.Indexers{})
			cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			objects := []runtime.Object{}

			if tt.auth != nil {
				authIndexer.Add(tt.auth)
			}

			if tt.caBundleConfigMap != nil {
				cmIndexer.Add(&baseCABundleConfigMap)
			}

			if tt.existingAuthConfigCM != nil {
				cmIndexer.Add(tt.existingAuthConfigCM)
				objects = append(objects, tt.existingAuthConfigCM)
			}

			cs := fake.NewSimpleClientset(objects...)
			if tt.cmApplyReaction != nil {
				// fake client's Apply() is a patch under the hood
				cs.PrependReactor("patch", "configmaps", tt.cmApplyReaction)
			}

			if tt.cmDeleteReaction != nil {
				cs.PrependReactor("delete", "configmaps", tt.cmDeleteReaction)
			}

			c := externalOIDCController{
				featureGateAccessor: tt.featureGates,
				configMaps:          cs.CoreV1(),
				authLister:          configv1listers.NewAuthenticationLister(authIndexer),
				configMapLister:     corev1listers.NewConfigMapLister(cmIndexer),
			}

			err := c.sync(testCtx, factory.NewSyncContext("externaloidc-test-context", events.NewInMemoryRecorder("externaloidc-test")))
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
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
	}{
		{
			name:              "auth config without OIDC providers",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders = nil
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with too many OIDC providers",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders = []configv1.OIDCProvider{{}, {}}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config non-https provider URL",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "http://insecure.com"
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config invalid provider URL",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "http://invalid        com"
					}
				},
			}),
			expectError: true,
		},
		{
			name:             "ca bundle configmap lister error",
			auth:             baseAuthResource,
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectError:      true,
		},
		{
			name:              "ca bundle configmap without required key",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapInvalidKey,
			expectError:       true,
		},
		{
			name:              "ca bundle configmap with invalid data",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapInvalidData,
			expectError:       true,
		},
		{
			name:              "ca bundle configmap with no data",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapNoData,
			expectError:       true,
		},
		{
			name:              "auth config nil prefix when required",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Claim: "username",
							},
							PrefixPolicy: configv1.Prefix,
							Prefix:       nil,
						}
					}
				},
			}),
			expectError: true,
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
						copy.Spec.OIDCProviders[i].ClaimValidationRules = append(copy.Spec.OIDCProviders[i].ClaimValidationRules, configv1.TokenClaimValidationRule{
							Type:          configv1.TokenValidationRuleTypeRequiredClaim,
							RequiredClaim: nil,
						})
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with invalid claim validation rule type",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(copy *configv1.Authentication) {
					for i := range copy.Spec.OIDCProviders {
						if len(copy.Spec.OIDCProviders[i].ClaimValidationRules) == 0 {
							copy.Spec.OIDCProviders[i].ClaimValidationRules = make([]configv1.TokenClaimValidationRule, 0)
						}
						copy.Spec.OIDCProviders[i].ClaimValidationRules = append(copy.Spec.OIDCProviders[i].ClaimValidationRules, configv1.TokenClaimValidationRule{
							Type:          "invalid",
							RequiredClaim: &configv1.TokenRequiredClaim{},
						})
					}
				},
			}),
			expectError: true,
		},
		{
			name:               "valid auth config",
			auth:               baseAuthResource,
			caBundleConfigMap:  &baseCABundleConfigMap,
			expectedAuthConfig: &baseAuthConfig,
			expectError:        false,
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
		},
		{
			name:              "auth config with default prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Claim: "username",
							},
							PrefixPolicy: configv1.NoOpinion,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To(""),
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with no prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Claim: "username",
							},
							PrefixPolicy: configv1.NoPrefix,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To("-"),
						}
					}
				},
			}),
			expectError: false,
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
			}

			gotConfig, err := c.generateAuthConfig(tt.auth)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}

			if !equality.Semantic.DeepEqual(tt.expectedAuthConfig, gotConfig) {
				t.Errorf("unexpected config diff: %s", diff.ObjectReflectDiff(tt.expectedAuthConfig, gotConfig))
			}
		})
	}
}

func TestExternalOIDCController_syncAuthConfig(t *testing.T) {
	testCtx := context.Background()
	for _, tt := range []struct {
		name                 string
		authConfig           apiserverv1beta1.AuthenticationConfiguration
		existingAuthConfigCM *corev1.ConfigMap
		configMapIndexer     cache.Indexer
		cmApplyReaction      k8stesting.ReactionFunc

		expectedAuthConfigJSON string
		expectSynced           bool
		expectError            bool
	}{
		{
			name:             "config map lister error",
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectSynced:     false,
			expectError:      true,
		},
		{
			name:                   "auth config same as existing",
			existingAuthConfigCM:   &baseAuthConfigCM,
			authConfig:             baseAuthConfig,
			expectedAuthConfigJSON: baseAuthConfigJSON,
			expectSynced:           false,
			expectError:            false,
		},
		{
			name: "error while creating new auth config",
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("error")
			},
			authConfig:   baseAuthConfig,
			expectSynced: false,
			expectError:  true,
		},
		{
			name:                   "new auth config",
			authConfig:             baseAuthConfig,
			expectedAuthConfigJSON: baseAuthConfigJSON,
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, &baseAuthConfigCM, nil
			},
			expectSynced: true,
			expectError:  false,
		},
		{
			name: "error while updating auth config",
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("error")
			},
			existingAuthConfigCM: &baseAuthConfigCM,
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To(""),
						}
					}

				},
			}),
			expectError:  true,
			expectSynced: false,
		},
		{
			name:                 "update auth config",
			existingAuthConfigCM: &baseAuthConfigCM,
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To(""),
						}
					}

				},
			}),
			expectedAuthConfigJSON: strings.ReplaceAll(baseAuthConfigJSON, "oidc-user:", ""),
			expectSynced:           true,
			expectError:            false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objects := []runtime.Object{}

			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.existingAuthConfigCM != nil {
				tt.configMapIndexer.Add(tt.existingAuthConfigCM)
				objects = append(objects, tt.existingAuthConfigCM)
			}

			var cs *fake.Clientset
			if tt.cmApplyReaction != nil {
				if _, obj, _ := tt.cmApplyReaction(nil); obj != nil {
					// add that object to the client object pool to simulate generation
					objects = append(objects, obj)
				}

				// fake client's Apply() is a patch under the hood
				cs = fake.NewSimpleClientset(objects...)
				cs.PrependReactor("patch", "configmaps", tt.cmApplyReaction)

			} else {
				cs = fake.NewSimpleClientset(objects...)
			}

			c := externalOIDCController{
				configMaps:      cs.CoreV1(),
				configMapLister: corev1listers.NewConfigMapLister(tt.configMapIndexer),
			}

			synced, err := c.syncAuthConfig(testCtx, tt.authConfig)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}

			if tt.expectSynced != synced {
				t.Errorf("expected synced %v; got %v", tt.expectSynced, synced)
			}

			if err != nil || !tt.expectSynced {
				// if we have encountered an error or we do not expect the sync to happen,
				// checking the configmap contents is irrelevant
				return
			}

			cm, err := c.configMaps.ConfigMaps(targetConfigMapNamespace).Get(testCtx, targetAuthConfigCMName, metav1.GetOptions{})
			if len(tt.expectedAuthConfigJSON) == 0 && cm != nil {
				t.Errorf("expected auth configmap to be missing, but it was found; error = %v", err)
			} else if len(tt.expectedAuthConfigJSON) > 0 && cm == nil {
				t.Errorf("expected auth configmap to exist but it was not found; error = %v", err)
			}

			if len(tt.expectedAuthConfigJSON) > 0 && tt.expectedAuthConfigJSON != cm.Data[authConfigDataKey] {
				t.Errorf("got unexpected auth-config data: %s", cm.Data[authConfigDataKey])
			}
		})
	}
}

func TestExternalOIDCController_validateAuthenticationConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name        string
		authConfig  apiserverv1beta1.AuthenticationConfiguration
		expectError bool
	}{
		{
			name:        "empty config",
			authConfig:  apiserverv1beta1.AuthenticationConfiguration{},
			expectError: true,
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
			name: "issuer with user in URL",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "https://username:password@secure.com"
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with query in URL",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "https://secure.com?query=true"
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with fragment in URL",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "https://secure.com/index.html#fragment"
				},
			}),
			expectError: true,
		},
		{
			name: "issuer without audiences",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.Audiences = []string{}
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with empty audience",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.Audiences = []string{
						"aud1",
						"",
					}
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with duplicate audience",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.Audiences = []string{
						"aud1",
						"aud2",
						"aud1",
					}
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
			name: "issuer with empty claim validation rule",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimValidationRules = []apiserverv1beta1.ClaimValidationRule{
						{
							Claim: "",
						},
					}
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with duplicate claim validation rule",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimValidationRules = []apiserverv1beta1.ClaimValidationRule{
						{
							Claim:         "claim1",
							RequiredValue: "val",
						},
						{
							Claim:         "claim2",
							RequiredValue: "val",
						},
						{
							Claim:         "claim1",
							RequiredValue: "val",
						},
					}
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with empty username claim",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimMappings.Username.Claim = ""
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with empty username prefix while claim exists",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimMappings.Username.Claim = "claim"
					authConfig.JWT[0].ClaimMappings.Username.Prefix = nil
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with empty groups prefix while claim exists",
			authConfig: *authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].ClaimMappings.Groups.Claim = "claim"
					authConfig.JWT[0].ClaimMappings.Groups.Prefix = nil
				},
			}),
			expectError: true,
		},
		{
			name:        "valid auth config",
			authConfig:  baseAuthConfig,
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateAuthenticationConfiguration(tt.authConfig)
			if tt.expectError && len(errs) == 0 {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && len(errs) > 0 {
				t.Errorf("did not expect any error but got: %v", errs)
			}

		})
	}
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

func newAuthConfig(jwt []apiserverv1beta1.JWTAuthenticator) *apiserverv1beta1.AuthenticationConfiguration {
	return &apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthenticationConfiguration",
			APIVersion: "apiserver.config.k8s.io/v1beta1",
		},
		JWT: jwt,
	}
}

func authConfigWithUpdates(authConfig apiserverv1beta1.AuthenticationConfiguration, updateFuncs []func(authConfig *apiserverv1beta1.AuthenticationConfiguration)) *apiserverv1beta1.AuthenticationConfiguration {
	copy := authConfig.DeepCopy()
	for _, updateFunc := range updateFuncs {
		updateFunc(copy)
	}
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
