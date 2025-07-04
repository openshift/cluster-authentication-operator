package routercerts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/client-go/kubernetes/fake"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	testlib "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestValidateRouterCertificates(t *testing.T) {
	defaultIngressCACerts := newCertificateAuthorityCertificate(nil)
	defaultIngressCertCM := newIngressConfigMap(string(withPEM(withExistingRootCA(defaultIngressCACerts))([]byte{})))

	fakeSystemRootCA := newCertificateAuthorityCertificate(nil)
	fakeSystemCertPool := x509.NewCertPool()
	fakeSystemCertPool.AddCert(fakeSystemRootCA.Certificate)

	testCases := []struct {
		name           string
		ingress        *configv1.Ingress
		secret         *corev1.Secret
		customSecret   *corev1.Secret
		cm             *corev1.ConfigMap
		systemCertPool func() (*x509.CertPool, error)
		expectedStatus operatorv1.ConditionStatus
		expectedReason string
	}{
		{
			name:           "NotDegraded",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionFalse,
			expectedReason: "AsExpected",
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication",
				withData("example.com",
					withPEM(
						withServer("*.example.com",
							withCA(
								withExistingRootCA(defaultIngressCACerts),
							),
						),
					),
				),
			),
		},
		{
			name:           "RootCAIsSystemCert",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionFalse,
			expectedReason: "AsExpected",
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withCA(
								withExistingRootCA(fakeSystemRootCA),
							),
						),
					),
					withMissingRootCA,
				),
			)),
			systemCertPool: func() (*x509.CertPool, error) { return fakeSystemCertPool, nil },
		},
		{
			name:           "NoIngressConfig",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoIngressConfig",
			secret:         newSecret("v4-0-config-system-router-certs", "openshift-authentication"),
		},
		{
			name:           "NoIngressDomain",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoIngressDomain",
			ingress:        newIngress("cluster"),
			secret:         newSecret("v4-0-config-system-router-certs", "openshift-authentication"),
		},
		{
			name:           "NoRouterCertSecret",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoRouterCertSecret",
			ingress:        newIngress("cluster", withDomain("example.com")),
		},
		{
			name:           "MissingRouterCertsPEM",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "MissingRouterCertsPEM",
			ingress:        newIngress("cluster", withDomain("example.com")),
			secret:         newSecret("v4-0-config-system-router-certs", "openshift-authentication"),
		},
		{
			name:           "MalformedRouterCertsPEM",
			ingress:        newIngress("cluster", withDomain("example.com")),
			secret:         newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com")),
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "MissingRouterCertsPEM",
		},
		{
			name:           "NoRootCARouterCerts",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoRootCARouterCerts",
			ingress:        newIngress("cluster", withDomain("example.com")),
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withCA(),
						),
					),
					withMissingRootCA,
				),
			)),
			cm:             newIngressConfigMap(string(withPEM(withCA(withCA()), withMissingRootCA)([]byte{}))),
			systemCertPool: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		},
		{
			name:    "NoServerCertRouterCerts",
			ingress: newIngress("cluster", withDomain("example.com")),
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com",
				withPEM(
					withCA(
						withExistingRootCA(defaultIngressCACerts),
					),
				),
			)),
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoServerCertRouterCerts",
		},
		{
			name:           "InvalidServerCertRouterCertsBadDNSName",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "InvalidServerCertRouterCerts",
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com",
				withPEM(
					withServer("*.example.org",
						withCA(
							withExistingRootCA(defaultIngressCACerts),
						),
					),
				),
			)),
		},
		{
			name:           "InvalidServerCertRouterCertsBadChain",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "InvalidServerCertRouterCerts",
			secret: newSecret("v4-0-config-system-router-certs", "openshift-authentication", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withExistingRootCA(defaultIngressCACerts),
						),
					),
					withMissingIntermediateCA,
				),
			)),
		},
		{
			name:           "CustomSecretNoOp",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionFalse,
			expectedReason: "AsExpected",

			customSecret: newSecret("v4-0-config-system-custom-router-certs", "openshift-authentication",
				withData(corev1.TLSCertKey,
					withPEM(
						withServer("*.example.com",
							withCA(
								withExistingRootCA(defaultIngressCACerts),
							),
						),
					),
				),
				withType(corev1.SecretTypeTLS)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}, &operatorv1.OperatorStatus{}, nil)
			ingresses := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.ingress != nil {
				err := ingresses.Add(tc.ingress)
				require.NoError(t, err)
			}
			secrets := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.secret != nil {
				err := secrets.Add(tc.secret)
				require.NoError(t, err)
			}
			if tc.customSecret != nil {
				err := secrets.Add(tc.customSecret)
				require.NoError(t, err)
			}
			if tc.systemCertPool == nil {
				tc.systemCertPool = x509.SystemCertPool
			}

			var err error
			configMapsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.cm != nil {
				err = configMapsIndexer.Add(tc.cm)
			} else {
				err = configMapsIndexer.Add(defaultIngressCertCM)
			}
			require.NoError(t, err)

			var secretsClient *fake.Clientset
			if tc.secret != nil {
				secretsClient = fake.NewSimpleClientset(tc.secret)
			} else {
				secretsClient = fake.NewSimpleClientset()
			}

			authIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			authIndexer.Add(&configv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.AuthenticationSpec{
					Type: configv1.AuthenticationTypeIntegratedOAuth,
				},
			})

			controller := routerCertsDomainValidationController{
				operatorClient:    operatorClient,
				ingressLister:     configv1listers.NewIngressLister(ingresses),
				secretLister:      corev1listers.NewSecretLister(secrets),
				configMapLister:   corev1listers.NewConfigMapLister(configMapsIndexer),
				secretNamespace:   "openshift-authentication",
				defaultSecretName: "v4-0-config-system-router-certs",
				customSecretName:  "v4-0-config-system-custom-router-certs",
				routeName:         "test-route",
				systemCertPool:    tc.systemCertPool,
				secretsClient:     secretsClient.CoreV1(),
				authConfigChecker: common.NewAuthConfigChecker(
					testlib.NewFakeInformer[configv1listers.AuthenticationLister](configv1listers.NewAuthenticationLister(authIndexer)),
					testlib.NewFakeInformer[operatorv1listers.KubeAPIServerLister](nil),
					testlib.NewFakeInformer[corelistersv1.ConfigMapLister](nil),
				),
			}
			err = controller.sync(context.TODO(), factory.NewSyncContext("testctx", events.NewInMemoryRecorder("test-recorder", clocktesting.NewFakePassiveClock(time.Now()))))
			require.NoError(t, err)
			_, s, _, _ := operatorClient.GetOperatorState()
			require.Len(t, s.Conditions, 1)
			condition := s.Conditions[0]
			require.Equal(t, "RouterCertsDegraded", condition.Type, mergepatch.ToYAMLOrError(s))
			require.Equal(t, tc.expectedReason, condition.Reason, mergepatch.ToYAMLOrError(s))
			require.Equal(t, tc.expectedStatus, condition.Status, mergepatch.ToYAMLOrError(s))
		})
	}
}

func newIngress(name string, options ...func(*configv1.Ingress)) *configv1.Ingress {
	ingress := &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	for _, f := range options {
		f(ingress)
	}
	return ingress
}

func withDomain(host string) func(*configv1.Ingress) {
	return func(ingress *configv1.Ingress) {
		ingress.Spec.Domain = host
	}
}

func newIngressConfigMap(data string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-ingress-cert",
			Namespace: "openshift-config-managed",
		},
		Data: map[string]string{"ca-bundle.crt": data},
	}
}

func newSecret(name, namespace string, options ...func(*corev1.Secret)) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	for _, f := range options {
		f(secret)
	}
	return secret
}

func withData(key string, options ...func([]byte) []byte) func(*corev1.Secret) {
	return func(secret *corev1.Secret) {
		var data []byte
		for _, f := range options {
			data = f(data)
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data[key] = data
	}
}

func withType(secretType corev1.SecretType, options ...func(*corev1.Secret)) func(*corev1.Secret) {
	return func(secret *corev1.Secret) {
		secret.Type = secretType
	}
}

func withPEM(options ...func([]*cryptoMaterials) []*cryptoMaterials) func([]byte) []byte {
	return func(bytes []byte) []byte {
		var certificates []*cryptoMaterials
		for _, f := range options {
			certificates = f(certificates)
		}
		for _, certificate := range certificates {
			bytes = append(bytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate.Raw})...)
		}
		return bytes
	}
}

func withServer(host string, options ...func([]*cryptoMaterials) []*cryptoMaterials) func([]*cryptoMaterials) []*cryptoMaterials {
	return func(certificates []*cryptoMaterials) []*cryptoMaterials {
		for _, f := range options {
			certificates = f(certificates)
		}
		var parent *cryptoMaterials
		if len(certificates) > 0 {
			parent = certificates[len(certificates)-1]
		}
		return append(certificates, newServerCertificate(parent, host))
	}
}

func withCA(options ...func([]*cryptoMaterials) []*cryptoMaterials) func([]*cryptoMaterials) []*cryptoMaterials {
	return func(certificates []*cryptoMaterials) []*cryptoMaterials {
		for _, f := range options {
			certificates = f(certificates)
		}
		var parent *cryptoMaterials
		if len(certificates) > 0 {
			parent = certificates[len(certificates)-1]
		}
		return append(certificates, newCertificateAuthorityCertificate(parent))
	}
}

func withExistingRootCA(rootCA *cryptoMaterials) func([]*cryptoMaterials) []*cryptoMaterials {
	return func(certificates []*cryptoMaterials) []*cryptoMaterials {
		if len(certificates) > 0 {
			panic("existing root CA must be added first")
		}
		return []*cryptoMaterials{rootCA}
	}
}

func withMissingRootCA(certificates []*cryptoMaterials) []*cryptoMaterials {
	if len(certificates) > 0 {
		certificate := certificates[0].Certificate
		if certificate.IsCA && bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
			return certificates[1:]
		}
	}
	return certificates
}

func withMissingIntermediateCA(certificates []*cryptoMaterials) []*cryptoMaterials {
	for i, certificate := range certificates {
		if certificate.Certificate.IsCA && !bytes.Equal(certificate.Certificate.RawSubject, certificate.Certificate.RawIssuer) {
			return append(certificates[:i], certificates[i+1:]...)
		}
	}
	return certificates
}

type cryptoMaterials struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

func newCertificateAuthorityCertificate(parent *cryptoMaterials) *cryptoMaterials {
	var err error
	result := &cryptoMaterials{}
	if result.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	var serialNumber *big.Int
	if serialNumber, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		panic(err)
	}
	var subject string
	if parent == nil {
		subject = fmt.Sprintf("RootCA_%v", serialNumber)
	} else {
		subject = fmt.Sprintf("IntermediateCA_%v", serialNumber)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signerCertificate := template
	signerPrivateKey := result.PrivateKey
	if parent != nil {
		signerCertificate = parent.Certificate
		signerPrivateKey = parent.PrivateKey
	}
	var der []byte
	if der, err = x509.CreateCertificate(rand.Reader, template, signerCertificate, result.PrivateKey.Public(), signerPrivateKey); err != nil {
		panic(err)
	}
	if result.Certificate, err = x509.ParseCertificate(der); err != nil {
		panic(err)
	}
	return result
}

func newServerCertificate(signer *cryptoMaterials, hosts ...string) *cryptoMaterials {
	var err error
	result := &cryptoMaterials{}
	if result.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	var serialNumber *big.Int
	if serialNumber, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: fmt.Sprintf("Server_%v", serialNumber)},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts,
	}
	var der []byte
	if der, err = x509.CreateCertificate(rand.Reader, template, signer.Certificate, result.PrivateKey.Public(), signer.PrivateKey); err != nil {
		panic(err)
	}
	if result.Certificate, err = x509.ParseCertificate(der); err != nil {
		panic(err)
	}
	return result
}
