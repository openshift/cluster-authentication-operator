package datasync

import (
	"crypto/x509"
	"fmt"
)

type ErrNoSAN struct {
	certSerialNumber string
	certIssuer       string
}

func (err ErrNoSAN) Error() string {
	return fmt.Sprintf("certificate relies on legacy Common Name field, use SANs instead:\n\tsn=%s;\n\tiss=%s", err.certSerialNumber, err.certIssuer)
}

func newErrNoSAN(cert *x509.Certificate) ErrNoSAN {
	return ErrNoSAN{
		certSerialNumber: cert.SerialNumber.String(),
		certIssuer:       cert.Issuer.String(),
	}
}
