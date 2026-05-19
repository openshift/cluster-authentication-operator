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
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	baseAuthConfig = apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthenticationConfiguration",
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
		},
		JWT: []apiserverv1beta1.JWTAuthenticator{
			{
				Issuer: apiserverv1beta1.Issuer{
					Audiences:            []string{"my-test-aud", "another-aud"},
					CertificateAuthority: "fake-ca-cert",
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

	baseAuthConfigJSON = `{"kind":"AuthenticationConfiguration","apiVersion":"apiserver.config.k8s.io/v1beta1","jwt":[{"issuer":{"url":"$URL","certificateAuthority":"fake-ca-cert","audiences":["my-test-aud","another-aud"],"audienceMatchPolicy":"MatchAny"},"claimValidationRules":[{"claim":"username","requiredValue":"test-username"},{"claim":"email","requiredValue":"test-email"}],"claimMappings":{"username":{"claim":"username","prefix":"oidc-user:"},"groups":{"claim":"groups","prefix":"oidc-group:"},"uid":{}}}]}`

	baseAuthConfigCM = corev1.ConfigMap{
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
)

const testIssuer = "https://issuer.openshift.io"

func TestExternalOIDCController_sync(t *testing.T) {
	testCtx := context.Background()

	for _, tt := range []struct {
		name string

		configMapIndexer     cache.Indexer
		existingAuthConfigCM *corev1.ConfigMap
		cmApplyReaction      k8stesting.ReactionFunc
		configGenerator      authConfigGenerator
		authType             configv1.AuthenticationType

		expectEvents           bool
		expectError            bool
		expectConfigMapDeleted bool
		excludeAuth            bool
	}{
		{
			name:        "auth resource not found",
			expectError: true,
			excludeAuth: true,
		},
		{
			name:     "auth type IntegratedOAuth and no auth configmap",
			authType: configv1.AuthenticationTypeIntegratedOAuth,
		},
		{
			name:             "auth type IntegratedOAuth delete error",
			configMapIndexer: &everFailingIndexer{},
			authType:         configv1.AuthenticationTypeIntegratedOAuth,
			expectError:      true,
		},
		{
			name:                   "auth type IntegratedOAuth configmap deleted",
			existingAuthConfigCM:   &baseAuthConfigCM,
			authType:               configv1.AuthenticationTypeIntegratedOAuth,
			expectEvents:           true,
			expectConfigMapDeleted: true,
		},
		{
			name:             "auth type OIDC but auth config generation fails",
			authType:         configv1.AuthenticationTypeOIDC,
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectEvents:     false,
			expectError:      true,
			configGenerator: &mockAuthConfigGenerator[*apiserverv1beta1.AuthenticationConfiguration]{
				err: errors.New("boom"),
			},
		},
		{
			name:     "auth type OIDC but apply config generation fails",
			authType: configv1.AuthenticationTypeOIDC,
			configGenerator: &mockAuthConfigGenerator[*apiserverv1beta1.AuthenticationConfiguration]{
				cfg: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
					func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
						authConfig.JWT[0].Issuer.URL = testIssuer
						authConfig.JWT[0].Issuer.CertificateAuthority = "ca-certificate"
					},
				}),
			},
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectEvents:     false,
			expectError:      true,
		},
		{
			name:                 "auth type OIDC config same as existing",
			existingAuthConfigCM: authConfigCMWithIssuerURL(&baseAuthConfigCM, testIssuer),
			authType:             configv1.AuthenticationTypeOIDC,
			configGenerator: &mockAuthConfigGenerator[*apiserverv1beta1.AuthenticationConfiguration]{
				cfg: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
					func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
						authConfig.JWT[0].Issuer.URL = testIssuer
					},
				}),
			},
			expectEvents: false,
		},
		{
			name: "auth type OIDC error while applying config",
			cmApplyReaction: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("apply failed")
			},
			authType:             configv1.AuthenticationTypeOIDC,
			existingAuthConfigCM: &baseAuthConfigCM,
			configGenerator: &mockAuthConfigGenerator[*apiserverv1beta1.AuthenticationConfiguration]{
				cfg: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
					func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
						authConfig.JWT[0].Issuer.URL = testIssuer
						authConfig.JWT[0].Issuer.Audiences = []string{"my-test-aud", "yet-another-aud"}
					},
				}),
			},
			expectEvents: false,
			expectError:  true,
		},
		{
			name:                 "auth type OIDC apply config",
			authType:             configv1.AuthenticationTypeOIDC,
			existingAuthConfigCM: authConfigCMWithIssuerURL(&baseAuthConfigCM, testIssuer),
			configGenerator: &mockAuthConfigGenerator[*apiserverv1beta1.AuthenticationConfiguration]{
				cfg: authConfigWithUpdates(baseAuthConfig, []func(authConfig *apiserverv1beta1.AuthenticationConfiguration){
					func(authConfig *apiserverv1beta1.AuthenticationConfiguration) {
						authConfig.JWT[0].Issuer.URL = testIssuer
						authConfig.JWT[0].Issuer.Audiences = []string{"my-test-aud", "yet-another-aud"}
					},
				}),
			},
			expectEvents: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objects := []runtime.Object{}

			authIndexer := cache.NewIndexer(func(obj interface{}) (string, error) {
				return "cluster", nil
			}, cache.Indexers{})

			if !tt.excludeAuth {
				authIndexer.Add(newAuthWithSpec(configv1.AuthenticationSpec{
					Type: tt.authType,
				}))
			}

			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
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
				name:                "test_oidc_controller",
				configMaps:          cs.CoreV1(),
				authLister:          configv1listers.NewAuthenticationLister(authIndexer),
				configMapLister:     corev1listers.NewConfigMapLister(tt.configMapIndexer),
				authConfigGenerator: tt.configGenerator,
			}

			eventRecorder := events.NewInMemoryRecorder("externaloidc-test", clocktesting.NewFakePassiveClock(time.Now()))

			err := c.sync(testCtx, factory.NewSyncContext("externaloidc-test-context", eventRecorder))

			if tt.expectError != (err != nil) {
				t.Fatalf("unexpected error; want: %v; got: %v", tt.expectError, err)
			}

			if tt.expectEvents != (len(eventRecorder.Events()) > 0) {
				t.Errorf("expected events: %v; got %v", tt.expectEvents, eventRecorder.Events())
			}

			if err != nil {
				// stop assertions here; the ones that follow are not relevant
				return
			}

			cm, err := c.configMaps.ConfigMaps(managedNamespace).Get(testCtx, targetAuthConfigCMName, metav1.GetOptions{})

			// happy path for deletion behavior, stop here if it matches our expectations.
			if apierrors.IsNotFound(err) && (tt.expectConfigMapDeleted || tt.authType != configv1.AuthenticationTypeOIDC) {
				return
			}

			if err != nil {
				t.Fatalf("received an unexpected error when getting ConfigMap with auth-config: %v", err)
			}

			cfg, err := tt.configGenerator.GenerateAuthenticationConfiguration(nil)
			if err != nil {
				t.Fatalf("received an unexpected error when generating auth config: %v", err)
			}

			expectedAuthConfigJSON, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("received an unexpected error when marshalling auth config: %v", err)
			}

			if string(expectedAuthConfigJSON) != cm.Data[authConfigDataKey] {
				t.Errorf("got unexpected auth-config data: '%s'\nexpected: '%s'", cm.Data[authConfigDataKey], string(expectedAuthConfigJSON))
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
			if tt.expectNotPresent != apierrors.IsNotFound(err) {
				t.Errorf("expected configmap to be deleted=%v; got: %v", tt.expectNotPresent, apierrors.IsNotFound(err))
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

func newAuthWithSpec(spec configv1.AuthenticationSpec) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: spec,
	}
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

type mockAuthConfigGenerator[T runtime.Object] struct {
	cfg T
	err error
}

func (macg *mockAuthConfigGenerator[T]) GenerateAuthenticationConfiguration(_ *configv1.Authentication) (runtime.Object, error) {
	return macg.cfg, macg.err
}
