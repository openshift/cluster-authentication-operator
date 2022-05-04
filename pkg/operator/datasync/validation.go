package datasync

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/keyutil"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
)

var validators = map[string]func(data []byte) []error{
	corev1.TLSCertKey:       validateClientCert,
	corev1.TLSPrivateKeyKey: ValidatePrivateKey,

	corev1.ServiceAccountRootCAKey: validateCACerts,
	configv1.ClientSecretKey:       noValidation,
	configv1.HTPasswdDataKey:       noValidation,
	configv1.BindPasswordKey:       noValidation,
}

func noValidation(_ []byte) []error { return []error{} }

func validateSecret(secretsLister corelistersv1.SecretLister, src sourceData) []error {
	s, err := secretsLister.Secrets("openshift-config").Get(src.Name)
	if err != nil {
		return []error{err}
	}

	data, exists := s.Data[src.Key]
	if !exists {
		return []error{fmt.Errorf("missing required key: %q", src.Key)}
	}

	return validators[src.Key](data)
}

func validateConfigMap(cmLister corelistersv1.ConfigMapLister, src sourceData) []error {
	cm, err := cmLister.ConfigMaps("openshift-config").Get(src.Name)
	if err != nil {
		return []error{err}
	}

	data, exists := cm.Data[src.Key]
	if !exists {
		return []error{fmt.Errorf("missing required key: %q", src.Key)}
	}

	return validators[src.Key]([]byte(data))
}

func validateClientCert(pem []byte) []error {
	errs := []error{}

	certs, certErrs := parseCerts(pem)
	errs = append(errs, certErrs...)

	if numCerts := len(certs); numCerts != 1 {
		return append(errs, fmt.Errorf("expected a single client certificate, got %d", numCerts))
	}

	cert := certs[0]
	clientAuthEKUFound := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			clientAuthEKUFound = true
			break
		}
	}
	if !clientAuthEKUFound {
		errs = append(errs, fmt.Errorf("expected the certificate to containe client authentication EKU"))
	}

	return errs
}

func ValidateServerCert(pem []byte) []error {
	errs := []error{}

	certs, certErrs := parseCerts(pem)
	errs = append(errs, certErrs...)

	if numCerts := len(certs); numCerts == 0 {
		return append(errs, fmt.Errorf("expected at least one server certificate"))
	}

	for _, cert := range certs {
		if !crypto.CertHasSAN(cert) {
			errs = append(errs, newErrNoSAN(cert))
		}
	}
	return errs
}

func ValidatePrivateKey(pemKey []byte) []error {
	if len(pemKey) == 0 {
		return []error{fmt.Errorf("required private key is empty")}
	}
	if _, err := keyutil.ParsePrivateKeyPEM(pemKey); err != nil {
		return []error{fmt.Errorf("failed to parse the private key")}
	}
	return []error{}
}

func validateCACerts(pem []byte) []error {
	errs := []error{}

	certs, certErrs := parseCerts(pem)
	errs = append(errs, certErrs...)

	if len(certs) == 0 {
		return append(errs, fmt.Errorf("no certificates found"))
	}

	return errs
}

func parseCerts(pemCerts []byte) ([]*x509.Certificate, []error) {
	certs := []*x509.Certificate{}

	if len(pemCerts) == 0 {
		return certs, []error{fmt.Errorf("required certificate is empty")}
	}

	errs := []error{}
	now := time.Now()

	cert, rest := pem.Decode(pemCerts)
	for ; cert != nil; cert, rest = pem.Decode(rest) {
		parsed, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse a certificate in the chain: %w", err))
			continue
		}

		if now.Before(parsed.NotBefore) {
			errs = append(errs, fmt.Errorf("certificate not yet valid:\n\tsub=%s;\n\tiss=%s", parsed.Subject, parsed.Issuer))
			continue
		}

		if now.After(parsed.NotAfter) {
			errs = append(errs, fmt.Errorf("certificate expired:\n\tsub=%s;\n\tiss=%s", parsed.Subject, parsed.Issuer))
			continue
		}

		certs = append(certs, parsed)
	}

	return certs, errs
}
