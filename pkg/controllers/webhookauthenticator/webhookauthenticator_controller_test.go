package webhookauthenticator

import (
	"context"
	"fmt"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	configfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

// fakeOIDCChecker implements oidcAvailabler for tests.
type fakeOIDCChecker struct {
	available bool
	err       error
}

func (f *fakeOIDCChecker) OIDCAvailable() (bool, error) {
	return f.available, f.err
}

// fakeWebhookSecretBuilder implements webhookSecretBuilder for tests.
type fakeWebhookSecretBuilder struct {
	secret *corev1.Secret
	err    error
}

func (f *fakeWebhookSecretBuilder) BuildWebhookSecret(_ context.Context, _ *corev1.Service, _, _ []byte) (*corev1.Secret, error) {
	return f.secret, f.err
}

type expectedCondition struct {
	condType string
	status   operatorv1.ConditionStatus
	reason   string
}

func findCondition(conditions []operatorv1.OperatorCondition, condType string) *operatorv1.OperatorCondition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

func newAuthentication(authType configv1.AuthenticationType, webhookSecretName string) *configv1.Authentication {
	auth := &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.AuthenticationSpec{
			Type: authType,
		},
	}
	if webhookSecretName != "" {
		auth.Spec.WebhookTokenAuthenticator = &configv1.WebhookTokenAuthenticator{
			KubeConfig: configv1.SecretNameReference{
				Name: webhookSecretName,
			},
		}
	}
	return auth
}

func newOAuthAPIService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: "openshift-oauth-apiserver",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Ports: []corev1.ServicePort{
				{Port: 443},
			},
		},
	}
}

func newAuthenticatorCertsSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openshift-authenticator-certs",
			Namespace: "openshift-oauth-apiserver",
		},
		Data: map[string][]byte{
			"tls.key": []byte("fake-key"),
			"tls.crt": []byte("fake-cert"),
		},
	}
}

func newWebhookKubeconfigSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhookSecretName,
			Namespace: configNamespace,
		},
		Data: map[string][]byte{
			"kubeConfig": []byte("fake-kubeconfig"),
		},
	}
}

func newFeatureGateAccessorWithError(err error) featuregates.FeatureGateAccess {
	ready := make(chan struct{})
	close(ready)
	return featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, ready, err)
}

func TestWebhookAuthenticatorControllerSync(t *testing.T) {
	type testcase struct {
		name                   string
		resources              []runtime.Object
		authentication         *configv1.Authentication
		featureGateAccessor    featuregates.FeatureGateAccess
		oidcChecker            oidcAvailabler
		webhookSecretBuilder   webhookSecretBuilder
		kubeClientFunc         func(*fake.Clientset)
		configClientFunc       func(*configfake.Clientset)
		expectError            bool
		expectedConditions     []expectedCondition
		expectedAuthentication *configv1.Authentication
		verifySecretDeleted    bool
		verifySecretCreated    bool
	}

	testcases := []testcase{
		{
			name:                "feature gates not yet observed",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, make(chan struct{}), nil),
			oidcChecker:         &fakeOIDCChecker{},
			expectError:         true,
		},
		{
			name:                "feature gates accessor returns error",
			featureGateAccessor: newFeatureGateAccessorWithError(fmt.Errorf("broken feature gates")),
			oidcChecker:         &fakeOIDCChecker{},
			expectError:         true,
		},
		{
			name:                "OIDC checker returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{err: fmt.Errorf("oidc check failed")},
			expectError:         true,
		},
		{
			name:                "OIDC available - removes webhook secret from openshift-config",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{available: true},
			resources: []runtime.Object{
				newWebhookKubeconfigSecret(),
			},
			verifySecretDeleted: true,
		},
		{
			name:                "OIDC available - no webhook secret to remove",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{available: true},
		},
		{
			name:                "OIDC available - removeOperands delete fails",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{available: true},
			resources: []runtime.Object{
				newWebhookKubeconfigSecret(),
			},
			kubeClientFunc: func(c *fake.Clientset) {
				c.PrependReactor("delete", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("delete failed")
				})
			},
			expectError: true,
		},
		{
			name:                "OIDC available - removeOperands secret deleted between list and delete",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{available: true},
			resources: []runtime.Object{
				newWebhookKubeconfigSecret(),
			},
			kubeClientFunc: func(c *fake.Clientset) {
				c.PrependReactor("delete", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(corev1.Resource("secrets"), webhookSecretName)
				})
			},
		},
		{
			name:                "auth type is not IntegratedOAuth - no-op",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication("LDAP", ""),
		},
		{
			name:                "authentication config Get fails",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			// authentication is nil so Get("cluster") returns not-found
			expectError: true,
		},
		{
			name:                "auth type is IntegratedOAuth - cert secret not found - progressing",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
			},
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionTrue, reason: "WaitingForCertKey"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - cert secret missing tls.key - progressing",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "openshift-authenticator-certs",
						Namespace: "openshift-oauth-apiserver",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("fake-cert"),
					},
				},
			},
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionTrue, reason: "WaitingForCertKey"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - cert secret missing tls.crt - progressing",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "openshift-authenticator-certs",
						Namespace: "openshift-oauth-apiserver",
					},
					Data: map[string][]byte{
						"tls.key": []byte("fake-key"),
					},
				},
			},
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionTrue, reason: "WaitingForCertKey"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - cert secret has empty tls.key",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "openshift-authenticator-certs",
						Namespace: "openshift-oauth-apiserver",
					},
					Data: map[string][]byte{
						"tls.key": {}, // present but empty
						"tls.crt": []byte("fake-cert"),
					},
				},
			},
			// Empty key passes the nil/existence checks in getAuthenticatorCertKeyPair
			// and is forwarded to BuildWebhookSecret, which proceeds normally.
			webhookSecretBuilder:   &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			expectedAuthentication: newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, webhookSecretName),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - BuildWebhookSecret fails",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder: &fakeWebhookSecretBuilder{err: fmt.Errorf("build failed")},
			expectError:          true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - ExternalOIDCExternalClaimsSourcing enabled - returns early after ensuring secret",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}, nil),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder: &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			// auth config should remain unchanged (no webhook field set)
			expectedAuthentication: newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - webhook kubeconfig needs update",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder:   &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			expectedAuthentication: newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, webhookSecretName),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - webhook kubeconfig set to wrong secret name",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, "old-webhook-secret"),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder:   &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			expectedAuthentication: newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, webhookSecretName),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - webhook kubeconfig already set correctly",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, webhookSecretName),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder:   &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			expectedAuthentication: newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, webhookSecretName),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is empty - defaults to IntegratedOAuth - webhook kubeconfig needs update",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication("", ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder:   &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			expectedAuthentication: newAuthentication("", webhookSecretName),
			verifySecretCreated:    true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
		{
			name:                "auth type is IntegratedOAuth - service not found",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			expectError:         true,
		},
		{
			name:                "auth type is IntegratedOAuth - authentication config Update fails",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateExternalOIDCExternalClaimsSourcing}),
			oidcChecker:         &fakeOIDCChecker{},
			authentication:      newAuthentication(configv1.AuthenticationTypeIntegratedOAuth, ""),
			resources: []runtime.Object{
				newOAuthAPIService(),
				newAuthenticatorCertsSecret(),
			},
			webhookSecretBuilder: &fakeWebhookSecretBuilder{secret: newWebhookKubeconfigSecret()},
			configClientFunc: func(c *configfake.Clientset) {
				c.PrependReactor("update", "authentications", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("update failed")
				})
			},
			expectError: true,
			expectedConditions: []expectedCondition{
				{condType: "AuthenticatorCertKeyProgressing", status: operatorv1.ConditionFalse, reason: "AsExpected"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the fake kube client and indexers from test resources.
			// Services and secrets need separate indexers because typed listers
			// do type assertions internally (e.g., obj.(*v1.Service)), so mixing
			// types in one indexer would panic. Secrets from different namespaces
			// can share a single indexer because SecretLister.Secrets(ns).Get(name)
			// filters by namespace via MetaNamespaceKeyFunc.
			kubeClient := fake.NewClientset(tc.resources...)
			if tc.kubeClientFunc != nil {
				tc.kubeClientFunc(kubeClient)
			}

			svcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			secretsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

			for _, obj := range tc.resources {
				switch o := obj.(type) {
				case *corev1.Service:
					if err := svcIndexer.Add(o); err != nil {
						t.Fatalf("failed to add service to indexer: %v", err)
					}
				case *corev1.Secret:
					if err := secretsIndexer.Add(o); err != nil {
						t.Fatalf("failed to add secret to indexer: %v", err)
					}
				}
			}

			// Set up the fake config client for Authentication.
			configObjects := []runtime.Object{}
			if tc.authentication != nil {
				configObjects = append(configObjects, tc.authentication)
			}
			configClient := configfake.NewClientset(configObjects...)
			if tc.configClientFunc != nil {
				tc.configClientFunc(configClient)
			}

			operatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
				&operatorv1.OperatorStatus{},
				nil,
			)

			cntrlr := &webhookAuthenticatorController{
				controllerInstanceName: "test-WebhookAuthenticator",
				authentication:         configClient.ConfigV1().Authentications(),
				svcLister:              corev1listers.NewServiceLister(svcIndexer),
				secrets:                kubeClient.CoreV1(),
				secretsLister:          corev1listers.NewSecretLister(secretsIndexer),
				configNSSecretsLister:  corev1listers.NewSecretLister(secretsIndexer),
				authConfigChecker:      tc.oidcChecker,
				operatorClient:         operatorClient,
				featureGateAccessor:    tc.featureGateAccessor,
				webhookSecretBuilder:   tc.webhookSecretBuilder,
			}

			syncCtx := factory.NewSyncContext(
				"test-sync",
				events.NewInMemoryRecorder("test-recorder", clocktesting.NewFakePassiveClock(time.Now())),
			)

			err := cntrlr.sync(context.Background(), syncCtx)

			// Validate error expectation.
			if tc.expectError != (err != nil) {
				t.Fatalf("expected error: %v; got: %v", tc.expectError, err)
			}

			// Validate operator status conditions.
			if len(tc.expectedConditions) > 0 {
				_, status, _, _ := operatorClient.GetOperatorState()
				for _, ec := range tc.expectedConditions {
					cond := findCondition(status.Conditions, ec.condType)
					if cond == nil {
						t.Errorf("expected condition %q to be set, but it was not found", ec.condType)
						continue
					}
					if cond.Status != ec.status {
						t.Errorf("expected condition %q status %q, got %q", ec.condType, ec.status, cond.Status)
					}
					if cond.Reason != ec.reason {
						t.Errorf("expected condition %q reason %q, got %q", ec.condType, ec.reason, cond.Reason)
					}
				}
			}

			// Validate the authentication config if expected.
			if tc.expectedAuthentication != nil {
				authConfig, err := configClient.ConfigV1().Authentications().Get(context.Background(), "cluster", metav1.GetOptions{})
				if err != nil {
					t.Fatalf("failed to get authentication config: %v", err)
				}
				if tc.expectedAuthentication.Spec.Type != authConfig.Spec.Type {
					t.Errorf("expected auth type %q, got %q", tc.expectedAuthentication.Spec.Type, authConfig.Spec.Type)
				}
				expectedWebhookName := ""
				if tc.expectedAuthentication.Spec.WebhookTokenAuthenticator != nil {
					expectedWebhookName = tc.expectedAuthentication.Spec.WebhookTokenAuthenticator.KubeConfig.Name
				}
				actualWebhookName := ""
				if authConfig.Spec.WebhookTokenAuthenticator != nil {
					actualWebhookName = authConfig.Spec.WebhookTokenAuthenticator.KubeConfig.Name
				}
				if expectedWebhookName != actualWebhookName {
					t.Errorf("expected webhook kubeconfig name %q, got %q", expectedWebhookName, actualWebhookName)
				}
			}

			// Validate webhook secret was deleted from openshift-config.
			if tc.verifySecretDeleted {
				_, err := kubeClient.CoreV1().Secrets(configNamespace).Get(context.Background(), webhookSecretName, metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Errorf("expected webhook secret to be deleted from %s, got: %v", configNamespace, err)
				}
			}

			// Validate webhook secret was created in openshift-config.
			if tc.verifySecretCreated {
				secret, err := kubeClient.CoreV1().Secrets(configNamespace).Get(context.Background(), webhookSecretName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("expected webhook secret to exist in %s: %v", configNamespace, err)
				} else if _, ok := secret.Data["kubeConfig"]; !ok {
					t.Errorf("expected webhook secret to contain 'kubeConfig' key")
				}
			}
		})
	}
}
