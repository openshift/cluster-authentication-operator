package kubeapiserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

var (
	testCertData = "fake-ca-cert"

	baseAuthResource = *newAuthWithSpec(configv1.AuthenticationSpec{
		Type: configv1.AuthenticationTypeOIDC,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: "test-oidc-provider",
				Issuer: configv1.TokenIssuer{
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

func TestAuthenticationConfigurationGeneratorGenerateAuthenticationConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string

		auth              configv1.Authentication
		caBundleConfigMap *corev1.ConfigMap
		configMapIndexer  cache.Indexer

		expectedAuthConfig *apiserverv1beta1.AuthenticationConfiguration
		expectError        bool
		featureGates       featuregates.FeatureGate
		configValidator    validationFunc
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
								Type:          configv1.TokenValidationRuleTypeRequiredClaim,
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
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
			),
		},
		{
			name:              "valid auth config during generation, validator fails",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
			),
			configValidator: func(_ *apiserverv1beta1.AuthenticationConfiguration) error {
				return errors.New("boom")
			},
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
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
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (http instead of https)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "http://insecure-url.com"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap, // ensure CA bundle exists
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (identical to issuer URL)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = auth.Spec.OIDCProviders[0].Issuer.URL
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (identical to issuer URL except trailing slash)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://issuer.example.com/"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (missing host)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https:///path"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (contains user info)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://user@discovery.example.com/path"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (contains query string)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://discovery.example.com/path?q=1"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (contains fragment)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://discovery.example.com/path#fragment"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "invalid discovery URL (parse error)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://%zz"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name: "user validation rule invalid  expression",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].UserValidationRules = []configv1.TokenUserValidationRule{
						{
							Expression: "", // invalid: empty expression
							Message:    "must have a valid expression",
						},
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{features.FeatureGateExternalOIDCWithUpstreamParity},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with invalid username expression, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "#@!$&*(^)",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with invalid groups expression, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "#@!$&*(^)",
							},
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression mapping",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Expression: "claims.sub",
						}
						authConfig.JWT[i].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with groups expression mapping",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "claims.groups",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Groups = apiserverv1beta1.PrefixedClaimOrExpression{
							Expression: "claims.groups",
						}
						authConfig.JWT[i].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username claim and expression both set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:      "username",
							Expression: "claims.email",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with groups claim and expression both set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Claim:      "groups",
								Expression: "claims.groups",
							},
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression and prefix set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression:   "claims.email",
							PrefixPolicy: configv1.Prefix,
							Prefix: &configv1.UsernamePrefix{
								PrefixString: "oidc-user:",
							},
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with groups expression and prefix set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "claims.groups",
							},
							Prefix: "oidc-group:",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression using claims.email without claims.email_verified, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
					}
				},
			}),
			expectError: true,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression using claims.email with claims.email_verified in claimValidationRule, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
						auth.Spec.OIDCProviders[i].ClaimValidationRules = []configv1.TokenClaimValidationRule{
							{
								Type: configv1.TokenValidationRuleTypeCEL,
								CEL: configv1.TokenClaimValidationCELRule{
									Expression: "claims.email_verified == true",
									Message:    "email must be verified",
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Expression: "claims.email",
						}
						authConfig.JWT[i].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
						authConfig.JWT[i].ClaimValidationRules = []apiserverv1beta1.ClaimValidationRule{
							{
								Expression: "claims.email_verified == true",
								Message:    "email must be verified",
							},
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression using both claims.email and claims.email_verified, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email_verified ? claims.email : 'unverified'",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Expression: "claims.email_verified ? claims.email : 'unverified'",
						}
						authConfig.JWT[i].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
			),
		},
		{
			name:              "auth config with username expression using claims.email with claims.email_verified in extra, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key:             "example.com/email-verified",
								ValueExpression: "claims.email_verified ? 'true' : 'false'",
							},
						}
						auth.Spec.OIDCProviders[i].ClaimValidationRules = []configv1.TokenClaimValidationRule{}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = apiserverv1beta1.PrefixedClaimOrExpression{
							Expression: "claims.email",
						}
						authConfig.JWT[i].ClaimMappings.UID = apiserverv1beta1.ClaimOrExpression{
							Claim: "sub",
						}
						authConfig.JWT[i].ClaimMappings.Extra = []apiserverv1beta1.ExtraMapping{
							{
								Key:             "example.com/email-verified",
								ValueExpression: "claims.email_verified ? 'true' : 'false'",
							},
						}
						authConfig.JWT[i].ClaimValidationRules = []apiserverv1beta1.ClaimValidationRule{}
					}
				},
			}),
			expectError: false,
			featureGates: featuregates.NewFeatureGate(
				[]configv1.FeatureGateName{
					features.FeatureGateExternalOIDCWithAdditionalClaimMappings,
					features.FeatureGateExternalOIDCWithUpstreamParity,
				},
				[]configv1.FeatureGateName{},
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

			c := NewAuthenticationConfigurationGenerator(corev1listers.NewConfigMapLister(tt.configMapIndexer), tt.featureGates)
			c.validationFn = tt.configValidator

			gotConfig, err := c.GenerateAuthenticationConfiguration(&tt.auth)
			if tt.expectError && err == nil {
				t.Fatalf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Fatalf("did not expect any error but got: %v", err)
			}

			if gotConfig == nil && tt.expectedAuthConfig == nil {
				return
			}

			if diff := cmp.Diff(tt.expectedAuthConfig, gotConfig, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("unexpected config diff: %s", diff)
			}
		})
	}
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

var (
	baseCACert, baseCAPrivateKey, validateTestCertData = func() (*x509.Certificate, crypto.Signer, string) {
		cert, key, err := generateCAKeyPair()
		if err != nil {
			panic(err)
		}
		return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}()

	validateBaseAuthConfig = apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       kindAuthenticationConfiguration,
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
		},
		JWT: []apiserverv1beta1.JWTAuthenticator{
			{
				Issuer: apiserverv1beta1.Issuer{
					Audiences:            []string{"my-test-aud", "another-aud"},
					CertificateAuthority: validateTestCertData,
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
		},
	}
)

func TestValidateApiserverAuthenticationConfiguration(t *testing.T) {
	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, nil)
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	for _, tt := range []struct {
		name        string
		authConfig  *apiserverv1beta1.AuthenticationConfiguration
		expectError bool
	}{
		{
			name:        "empty config",
			authConfig:  &apiserverv1beta1.AuthenticationConfiguration{},
			expectError: false,
		},
		{
			name:        "nil config",
			authConfig:  nil,
			expectError: false,
		},
		{
			name: "issuer with empty URL",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = ""
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with http URL",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "http://insecure.com"
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with invalid CA",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.CertificateAuthority = "invalid CA"
				},
			}),
			expectError: true,
		},
		{
			name: "valid auth config",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
				func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = testServer.URL
				},
			}),
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApiserverAuthenticationConfiguration(tt.authConfig)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}
		})
	}
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
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("PEM encoding certificate: %w", err)
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, fmt.Errorf("PEM encoding private key: %w", err)
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &serverCert, nil
}
