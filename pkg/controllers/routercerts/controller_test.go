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
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestValidateRouterCertificates(t *testing.T) {

	fakeSystemRootCA := newCertificateAuthorityCertificate(nil)
	fakeSystemCertPool := x509.NewCertPool()
	fakeSystemCertPool.AddCert(fakeSystemRootCA.Certificate)

	var err error
	testCases := []struct {
		name           string
		ingress        *configv1.Ingress
		secret         *corev1.Secret
		systemCertPool func() (*x509.CertPool, error)
		expectedStatus operatorv1.ConditionStatus
		expectedReason string
	}{
		{
			name:           "NotDegraded",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionFalse,
			expectedReason: "AsExpected",
			secret: newSecret("router-certs", "target", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withCA(),
						),
					),
				),
			)),
		},
		{
			name:           "RootCAIsSystemCert",
			ingress:        newIngress("cluster", withDomain("example.com")),
			expectedStatus: operatorv1.ConditionFalse,
			expectedReason: "AsExpected",
			secret: newSecret("router-certs", "target", withData("example.com",
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
			secret:         newSecret("router-certs", "target"),
		},
		{
			name:           "NoIngressDomain",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoIngressDomain",
			ingress:        newIngress("cluster"),
			secret:         newSecret("router-certs", "target"),
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
			secret:         newSecret("router-certs", "target"),
		},
		{
			name:           "MalformedRouterCertsPEM",
			ingress:        newIngress("cluster", withDomain("example.com")),
			secret:         newSecret("router-certs", "target", withData("example.com")),
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "MissingRouterCertsPEM",
		},
		{
			name:           "NoRootCARouterCerts",
			expectedStatus: operatorv1.ConditionTrue,
			expectedReason: "NoRootCARouterCerts",
			ingress:        newIngress("cluster", withDomain("example.com")),
			secret: newSecret("router-certs", "target", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withCA(),
						),
					),
					withMissingRootCA,
				),
			)),
			systemCertPool: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		},
		{
			name:    "NoServerCertRouterCerts",
			ingress: newIngress("cluster", withDomain("example.com")),
			secret: newSecret("router-certs", "target", withData("example.com",
				withPEM(
					withCA(
						withCA(),
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
			secret: newSecret("router-certs", "target", withData("example.com",
				withPEM(
					withServer("*.example.org",
						withCA(
							withCA(),
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
			secret: newSecret("router-certs", "target", withData("example.com",
				withPEM(
					withServer("*.example.com",
						withCA(
							withCA(),
						),
					),
					withMissingIntermediateCA,
				),
			)),
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
			if tc.systemCertPool == nil {
				tc.systemCertPool = x509.SystemCertPool
			}
			controller := routerCertsDomainValidationController{
				operatorClient:  operatorClient,
				ingressLister:   configv1listers.NewIngressLister(ingresses),
				secretLister:    corev1listers.NewSecretLister(secrets),
				targetNamespace: "target",
				secretName:      "router-certs",
				routeName:       "test-route",
				systemCertPool:  tc.systemCertPool,
			}
			err = controller.sync(context.TODO(), nil)
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
