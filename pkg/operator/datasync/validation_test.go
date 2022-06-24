package datasync

import (
	"fmt"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func Test_validateSecret(t *testing.T) {
	tests := []struct {
		name    string
		src     sourceData
		secrets []*corev1.Secret
		want    []error
	}{
		{
			name: "secret missing",
			src:  sourceData{Name: "somesecret", Key: corev1.TLSPrivateKeyKey},
			want: []error{
				fmt.Errorf("secret \"somesecret\" not found"),
			},
		},
		{
			name: "missing required field",
			src:  sourceData{Name: "somesecret", Key: configv1.ClientSecretKey},
			want: []error{
				fmt.Errorf("missing required key: \"clientSecret\""),
			},
			secrets: []*corev1.Secret{
				testSecret("somesecret", map[string][]byte{"randomkey": []byte("hi mom")}),
			},
		},
		{
			name: "invalid value in required field",
			src:  sourceData{Name: "somesecret", Key: corev1.TLSPrivateKeyKey},
			want: []error{
				fmt.Errorf("failed to parse the private key"),
			},
			secrets: []*corev1.Secret{
				testSecret("somesecret", map[string][]byte{corev1.TLSPrivateKeyKey: []byte("invalid value")}),
			},
		},
		{
			name: "happy path",
			src:  sourceData{Name: "somesecret", Key: corev1.TLSPrivateKeyKey},
			secrets: []*corev1.Secret{
				testSecret("somesecret", map[string][]byte{
					corev1.TLSPrivateKeyKey: []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCJVbFNXgGuaYV2pNhCTD9bI7HxdzpKtN8pu+IxAc+zknQSLjHI
U09t/ueGp3Ay9iWhn2wcVtTWS7AfKUvUOGkB8gygdPIYHVQxsHg7jLrArVyogZGg
mc/rd4do9+xtNQgbwHZfjbnot4kQrVpS+SU/b8PPpwgP3m1ftayG+vfOXQIDAQAB
AoGAdWGP5K+3wiogz9J/oNLox+5PdjJQ2W+U2mfjIb4Jl9NScAOZuz4xwrM/kqDk
TjqC2YyYa/RvgCY7B7dVP7NjU+JnhfeMjR9tRckoHJk8coAD52Xk/HuJ4aCYEy7E
eqeyDZUwFjNeueCdz+gGE50D6n0Ml7xB7siSHp98r3vqVkECQQDx1se+KB29BxjN
X4f89Q0b4jnHYsJQwzO0ijKy+Ns2X4qbzypAC6Y9NcLel4VgjAs0JpKzZNWNzMIH
VSJWZ5fNAkEAkWBe3z33fOd90ENdiiVpb/xnFjmpUaBUgPlPX8s2pQwXThQ5Xmv0
OtQSVhpiM0+ocuGeVGnHtvtt+XXeDVhg0QJAKyUSRY6Kn6qgdiNQ84QUbqERhczM
tfPdSZxOJzfWhADPjbSL6Rkq80igF24Y0Xyqkwc+rNqUbtPU2dIKajfZEQJAZof/
oZfEy1VBiPdaK6rDOHZeBnDYmHdp4iTz9G4QtktWzHy7EXs2H5+e5xdolyPhfFTg
JE0OzGF8aOrWl7bzYQJAXiNL4YZV39TvQClKj3LPR4O9tggRl775wX4tY04Re0zf
HOZ5Dsbrjl60/qaXpg5uB0ZqDm7yhI44k3C5LYdJIg==
-----END RSA PRIVATE KEY-----`)}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, s := range tt.secrets {
				indexer.Add(s)
			}
			secretsLister := corev1listers.NewSecretLister(indexer)

			got := validateSecret(secretsLister, tt.src)
			gotAggr := errors.NewAggregate(got)
			wantAggr := errors.NewAggregate(tt.want)
			if gotAggr != nil && wantAggr != nil {
				if gotAggr.Error() != wantAggr.Error() {
					t.Errorf("validateSecret() = %v, want %v", got, tt.want)
				}
			} else if gotAggr != nil || wantAggr != nil { // one of them is nil but not both
				t.Errorf("validateSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateConfigMap(t *testing.T) {
	tests := []struct {
		name       string
		src        sourceData
		configMaps []*corev1.ConfigMap
		want       []error
	}{
		{
			name: "configMap missing",
			src:  sourceData{Name: "someCM", Key: corev1.ServiceAccountRootCAKey},
			want: []error{
				fmt.Errorf("configmap \"someCM\" not found"),
			},
		},
		{
			name: "missing required field",
			src:  sourceData{Name: "someCM", Key: corev1.ServiceAccountRootCAKey},
			want: []error{
				fmt.Errorf("missing required key: \"ca.crt\""),
			},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{"randomkey": "random value"}),
			},
		},
		{
			name: "invalid value in required field",
			src:  sourceData{Name: "someCM", Key: corev1.ServiceAccountRootCAKey},
			want: []error{
				fmt.Errorf("no certificates found"),
			},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{corev1.ServiceAccountRootCAKey: "invalid value"}),
			},
		},
		{
			name: "expired cert in the bundle",
			src:  sourceData{Name: "someCM", Key: corev1.ServiceAccountRootCAKey},
			want: []error{
				fmt.Errorf("certificate expired:\n\tsub=CN=*,OU=IT Department,O=Global Security,L=London,ST=London,C=GB;\n\tiss=CN=*,OU=IT Department,O=Global Security,L=London,ST=London,C=GB"),
			},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{
					corev1.ServiceAccountRootCAKey: `
-----BEGIN CERTIFICATE-----
MIIFjjCCA3agAwIBAgIUfyOztjOh4PRqmLZ/sAf0uVC7I2YwDQYJKoZIhvcNAQEN
BQAwTzELMAkGA1UEBhMCQ1oxEDAOBgNVBAgMB01vcmF2aWExHDAaBgNVBAoME015
IFByaXZhdGUgT3JnIEx0ZC4xEDAOBgNVBAMMB1Rlc3QgQ0EwIBcNMjAwNjA0MTEx
NTMyWhgPMzAyMTAyMTcxMTE1MzJaME8xCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdN
b3JhdmlhMRwwGgYDVQQKDBNNeSBQcml2YXRlIE9yZyBMdGQuMRAwDgYDVQQDDAdU
ZXN0IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuUv94+86LR7/
ZLGFnRnRMfum5GnB9zpCRC4iDcgeRMs/EPOFZhvm++fUHXFefe9spt/SKCv1DEgt
z+n4wqY8GEM4mTDn6RfEinpSzs+ID8ks+C/duaDHF1vo+MH91mchOSNrrH0c6xx7
9WPyIz38J92H3/tDSi4p7SjbAYIM+IDRXlT9wgosWZdolGVpbxUt1Jsb0LzCYYdc
VCpvLWJBnrXGPta1uMQmOv+U+ZIbHK8jMrR6Fgn4wOz4JX0cqyvWm6f0NvtfND/2
AY1c7lZ2cY2JLZsMxifJyVqSjH2CPEWbF/HhxSL3wKLjzmLllSgy2iAqfbWnZIUJ
choMS8ODT6mahPUHk+1JngSIjhHqr7ihg8z5CxkMF+/HURs4D+kXyDOrr0YkmQev
OG+/Y74DMa2Zz8B1qtRzQy/mfGfIymWZ+XmRC7oP+37WYlXFhMNw0QVfWbV3kIxB
kzrO8fg1KtsJiu8j2F0mU/aYAf0XHLaUQy84L+/DnVYl9pL/pK5Mr464bYFhx3B4
qD8TOMfRC5R+gQYT1cbu9FX+RWIg58hBTO77jy3c70u6Ni5NorENqpy9eIek7n7D
A1o1P8XxKPCwcm+LDv3r9p8iDAU9/By0tkyJUhum8xksp2Z1g3AMqkWSfr6WiiWg
Tgvy0Jomfjq6IMjjM24IrIvVggJIjeUCAwEAAaNgMF4wHQYDVR0OBBYEFCpl6lKY
LCYbDb6tPqlw0MTeclimMB8GA1UdIwQYMBaAFCpl6lKYLCYbDb6tPqlw0MTeclim
MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBDQUAA4IC
AQBEMIODzSMbG99IS2lzwdIlNPQaHORqNWZq/XfgIr5anoyhkykTV++u/+tl4WPN
3xAuqduHGP9ReQrmrcmixafOoa30tVO4WfohQQW0W/IwS9wgCNZ3bzjyXcTj2nAF
eGqL2812EW0bVr29sIu7MG+8p0AtzRsY81uZaWSdaZWCOKz0xRAbqSlubPyCtmiX
z1fD+Ge2eyVNvec2sn4+EoAUt57VVDTFOTlMPER/XTZU1845kscSAlgFG6tXtU4A
uMrTnJGegO0flBALQc7ts6L3p6yf+V8pFcf5T2wtT9ysxi1YLyQ6sB2nWLlTuXUq
f0z8ABZ4zXcLNkDa0BYs+JCSb3VCgOX//6VB/wTquJbRobA/hy7YDi6RcQ0NaDct
Qi+urEhLGZ6NHD6zDXukYbQgepQ9dHjS/BzSHHPO5TzkvwnDTGjTItoEMaF0UFMJ
iB1AypebxA5tV8ZDDcVOvpP4YJUHkZ0gqf2nKtsfMhsu9m/6MwP+9jSFnfsDKnGO
/CjUlhHLm61UqD62rJtCe5BxA8FaJFh6WaEFiWtEdEpSJRDblZFo4AG2U9iudqW6
xDqO/vzD5bN+PsDvrPsG0N04iUc5OFJ28mgNqUzxshcPb+TU/WZrDLB4atf6dKcy
EOmzjRGqVe4mm6ztYuO8QONBfdsEDRqqiKQyYkMZbh6Vow==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICIzCCAc2gAwIBAgIJAOApTlMFDOUnMA0GCSqGSIb3DQEBCwUAMG0xCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEYMBYGA1UE
CgwPR2xvYmFsIFNlY3VyaXR5MRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MQowCAYD
VQQDDAEqMB4XDTE3MTAwNDIwNDgzOFoXDTE3MTAwMzIwNDgzOFowbTELMAkGA1UE
BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRgwFgYDVQQK
DA9HbG9iYWwgU2VjdXJpdHkxFjAUBgNVBAsMDUlUIERlcGFydG1lbnQxCjAIBgNV
BAMMASowXDANBgkqhkiG9w0BAQEFAANLADBIAkEA3Gt0KmuRXDxvqZUiX/xqAn1t
nZZX98guZvPPyxnQtV3YpA274W0sX3jL+U71Ya+3kaUstXQa4YrWBUHiXoqJnwID
AQABo1AwTjAdBgNVHQ4EFgQUtDsIpzHoUiLsO88f9fm+G0tYSPowHwYDVR0jBBgw
FoAUtDsIpzHoUiLsO88f9fm+G0tYSPowDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAANBADfrlKof5CUkxGlX9Rifxv/mWOk8ZuTLWfMYQH2nycBHnmOxy6sR+87W
/Mb/uRz0TXVnGVcbu5E8Bz7e/Far1ZI=
-----END CERTIFICATE-----`}),
			},
		},
		{
			name: "happy path",
			src:  sourceData{Name: "someCM", Key: corev1.ServiceAccountRootCAKey},
			want: []error{},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{
					corev1.ServiceAccountRootCAKey: `
-----BEGIN CERTIFICATE-----
MIIFjjCCA3agAwIBAgIUfyOztjOh4PRqmLZ/sAf0uVC7I2YwDQYJKoZIhvcNAQEN
BQAwTzELMAkGA1UEBhMCQ1oxEDAOBgNVBAgMB01vcmF2aWExHDAaBgNVBAoME015
IFByaXZhdGUgT3JnIEx0ZC4xEDAOBgNVBAMMB1Rlc3QgQ0EwIBcNMjAwNjA0MTEx
NTMyWhgPMzAyMTAyMTcxMTE1MzJaME8xCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdN
b3JhdmlhMRwwGgYDVQQKDBNNeSBQcml2YXRlIE9yZyBMdGQuMRAwDgYDVQQDDAdU
ZXN0IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuUv94+86LR7/
ZLGFnRnRMfum5GnB9zpCRC4iDcgeRMs/EPOFZhvm++fUHXFefe9spt/SKCv1DEgt
z+n4wqY8GEM4mTDn6RfEinpSzs+ID8ks+C/duaDHF1vo+MH91mchOSNrrH0c6xx7
9WPyIz38J92H3/tDSi4p7SjbAYIM+IDRXlT9wgosWZdolGVpbxUt1Jsb0LzCYYdc
VCpvLWJBnrXGPta1uMQmOv+U+ZIbHK8jMrR6Fgn4wOz4JX0cqyvWm6f0NvtfND/2
AY1c7lZ2cY2JLZsMxifJyVqSjH2CPEWbF/HhxSL3wKLjzmLllSgy2iAqfbWnZIUJ
choMS8ODT6mahPUHk+1JngSIjhHqr7ihg8z5CxkMF+/HURs4D+kXyDOrr0YkmQev
OG+/Y74DMa2Zz8B1qtRzQy/mfGfIymWZ+XmRC7oP+37WYlXFhMNw0QVfWbV3kIxB
kzrO8fg1KtsJiu8j2F0mU/aYAf0XHLaUQy84L+/DnVYl9pL/pK5Mr464bYFhx3B4
qD8TOMfRC5R+gQYT1cbu9FX+RWIg58hBTO77jy3c70u6Ni5NorENqpy9eIek7n7D
A1o1P8XxKPCwcm+LDv3r9p8iDAU9/By0tkyJUhum8xksp2Z1g3AMqkWSfr6WiiWg
Tgvy0Jomfjq6IMjjM24IrIvVggJIjeUCAwEAAaNgMF4wHQYDVR0OBBYEFCpl6lKY
LCYbDb6tPqlw0MTeclimMB8GA1UdIwQYMBaAFCpl6lKYLCYbDb6tPqlw0MTeclim
MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBDQUAA4IC
AQBEMIODzSMbG99IS2lzwdIlNPQaHORqNWZq/XfgIr5anoyhkykTV++u/+tl4WPN
3xAuqduHGP9ReQrmrcmixafOoa30tVO4WfohQQW0W/IwS9wgCNZ3bzjyXcTj2nAF
eGqL2812EW0bVr29sIu7MG+8p0AtzRsY81uZaWSdaZWCOKz0xRAbqSlubPyCtmiX
z1fD+Ge2eyVNvec2sn4+EoAUt57VVDTFOTlMPER/XTZU1845kscSAlgFG6tXtU4A
uMrTnJGegO0flBALQc7ts6L3p6yf+V8pFcf5T2wtT9ysxi1YLyQ6sB2nWLlTuXUq
f0z8ABZ4zXcLNkDa0BYs+JCSb3VCgOX//6VB/wTquJbRobA/hy7YDi6RcQ0NaDct
Qi+urEhLGZ6NHD6zDXukYbQgepQ9dHjS/BzSHHPO5TzkvwnDTGjTItoEMaF0UFMJ
iB1AypebxA5tV8ZDDcVOvpP4YJUHkZ0gqf2nKtsfMhsu9m/6MwP+9jSFnfsDKnGO
/CjUlhHLm61UqD62rJtCe5BxA8FaJFh6WaEFiWtEdEpSJRDblZFo4AG2U9iudqW6
xDqO/vzD5bN+PsDvrPsG0N04iUc5OFJ28mgNqUzxshcPb+TU/WZrDLB4atf6dKcy
EOmzjRGqVe4mm6ztYuO8QONBfdsEDRqqiKQyYkMZbh6Vow==
-----END CERTIFICATE-----`}),
			},
		},
		{
			name: "client certificate without client authentication EKU",
			src:  sourceData{Name: "someCM", Key: corev1.TLSCertKey},
			want: []error{fmt.Errorf("expected the certificate to containe client authentication EKU")},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{
					corev1.TLSCertKey: `
-----BEGIN CERTIFICATE-----
MIIFjjCCA3agAwIBAgIUfyOztjOh4PRqmLZ/sAf0uVC7I2YwDQYJKoZIhvcNAQEN
BQAwTzELMAkGA1UEBhMCQ1oxEDAOBgNVBAgMB01vcmF2aWExHDAaBgNVBAoME015
IFByaXZhdGUgT3JnIEx0ZC4xEDAOBgNVBAMMB1Rlc3QgQ0EwIBcNMjAwNjA0MTEx
NTMyWhgPMzAyMTAyMTcxMTE1MzJaME8xCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdN
b3JhdmlhMRwwGgYDVQQKDBNNeSBQcml2YXRlIE9yZyBMdGQuMRAwDgYDVQQDDAdU
ZXN0IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuUv94+86LR7/
ZLGFnRnRMfum5GnB9zpCRC4iDcgeRMs/EPOFZhvm++fUHXFefe9spt/SKCv1DEgt
z+n4wqY8GEM4mTDn6RfEinpSzs+ID8ks+C/duaDHF1vo+MH91mchOSNrrH0c6xx7
9WPyIz38J92H3/tDSi4p7SjbAYIM+IDRXlT9wgosWZdolGVpbxUt1Jsb0LzCYYdc
VCpvLWJBnrXGPta1uMQmOv+U+ZIbHK8jMrR6Fgn4wOz4JX0cqyvWm6f0NvtfND/2
AY1c7lZ2cY2JLZsMxifJyVqSjH2CPEWbF/HhxSL3wKLjzmLllSgy2iAqfbWnZIUJ
choMS8ODT6mahPUHk+1JngSIjhHqr7ihg8z5CxkMF+/HURs4D+kXyDOrr0YkmQev
OG+/Y74DMa2Zz8B1qtRzQy/mfGfIymWZ+XmRC7oP+37WYlXFhMNw0QVfWbV3kIxB
kzrO8fg1KtsJiu8j2F0mU/aYAf0XHLaUQy84L+/DnVYl9pL/pK5Mr464bYFhx3B4
qD8TOMfRC5R+gQYT1cbu9FX+RWIg58hBTO77jy3c70u6Ni5NorENqpy9eIek7n7D
A1o1P8XxKPCwcm+LDv3r9p8iDAU9/By0tkyJUhum8xksp2Z1g3AMqkWSfr6WiiWg
Tgvy0Jomfjq6IMjjM24IrIvVggJIjeUCAwEAAaNgMF4wHQYDVR0OBBYEFCpl6lKY
LCYbDb6tPqlw0MTeclimMB8GA1UdIwQYMBaAFCpl6lKYLCYbDb6tPqlw0MTeclim
MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBDQUAA4IC
AQBEMIODzSMbG99IS2lzwdIlNPQaHORqNWZq/XfgIr5anoyhkykTV++u/+tl4WPN
3xAuqduHGP9ReQrmrcmixafOoa30tVO4WfohQQW0W/IwS9wgCNZ3bzjyXcTj2nAF
eGqL2812EW0bVr29sIu7MG+8p0AtzRsY81uZaWSdaZWCOKz0xRAbqSlubPyCtmiX
z1fD+Ge2eyVNvec2sn4+EoAUt57VVDTFOTlMPER/XTZU1845kscSAlgFG6tXtU4A
uMrTnJGegO0flBALQc7ts6L3p6yf+V8pFcf5T2wtT9ysxi1YLyQ6sB2nWLlTuXUq
f0z8ABZ4zXcLNkDa0BYs+JCSb3VCgOX//6VB/wTquJbRobA/hy7YDi6RcQ0NaDct
Qi+urEhLGZ6NHD6zDXukYbQgepQ9dHjS/BzSHHPO5TzkvwnDTGjTItoEMaF0UFMJ
iB1AypebxA5tV8ZDDcVOvpP4YJUHkZ0gqf2nKtsfMhsu9m/6MwP+9jSFnfsDKnGO
/CjUlhHLm61UqD62rJtCe5BxA8FaJFh6WaEFiWtEdEpSJRDblZFo4AG2U9iudqW6
xDqO/vzD5bN+PsDvrPsG0N04iUc5OFJ28mgNqUzxshcPb+TU/WZrDLB4atf6dKcy
EOmzjRGqVe4mm6ztYuO8QONBfdsEDRqqiKQyYkMZbh6Vow==
-----END CERTIFICATE-----`}),
			},
		},
		{
			name: "client certificate happy path",
			src:  sourceData{Name: "someCM", Key: corev1.TLSCertKey},
			want: []error{},
			configMaps: []*corev1.ConfigMap{
				testConfigMap("someCM", map[string]string{
					corev1.TLSCertKey: `
-----BEGIN CERTIFICATE-----
MIIFuDCCA6CgAwIBAgIUK2S4cHHMj/SMctvuBCYuyMMZYHowDQYJKoZIhvcNAQEL
BQAwTzELMAkGA1UEBhMCQ1oxEDAOBgNVBAgMB01vcmF2aWExHDAaBgNVBAoME015
IFByaXZhdGUgT3JnIEx0ZC4xEDAOBgNVBAMMB1Rlc3QgQ0EwIBcNMjAwNjA0MTIx
MTAwWhgPMjMwMDEwMTUxMjExMDBaMFUxCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdN
b3JhdmlhMRwwGgYDVQQKDBNNeSBQcml2YXRlIE9yZyBMdGQuMRYwFAYDVQQDDA1z
b21ld2hlcmUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAprVK
HfYJqBUydCdHtlyvPhAwmdM3bFc3A+cthANrlMEybngZPeJAVcywYht/yqbmJ43y
13CQln19jV8j0MyCtVEfSY2Ji3Gk0gFaL6KywKQpIVrnXc80rxiL24wJ9maDFNy/
C637v9plGkIwzRTAzyPKE/khPtgts4InZHZDkQl7OuC6HeUNHPZpm7HUuA2uIhlp
mxOcD0ifAiWFufS2Nqbu9Ksl1j7QFs6KUBR79Ry3q82DnI3x2Id/Zpw4SbYLKuuY
IVVoY2Z8gZ8oNMiY7p6FQN23DUVNQw2IUjM9F7JZ8rt9xF535KNu0X8HYfrhXnRs
l+NVa/5kGX4aJDqgYt6YjU0x+3B5imLLFPjUomPR5e7AQp3bdcUtSKqWl7+0v1YM
uiYmosU0D/uSDJy19SDMSEIoh2IVvA2Q/L/ROkxMjfgFwmGMOJa4if/nUsoGKSSz
PVx+3kMk1yRDrdcbnXuCtdpUw3/+XADTSO30teumGRF3wxGmo66F1ddm8f1+uhi6
QW/EYKQ1JJnjTMHVNArzNgNp4EikJ8+1fqL+SZMQGBdTaYJja59XtOLLWVpjWeLE
o6hvJa6PsLzds8xMtXyyTw29FXJs4YEqHVldfy6Qo0pwdcANVleXKvhYIlb/d7y2
bTemM25zU6Zjyt+GCz7D9mzlalaGFljOm42Eba8CAwEAAaOBgzCBgDAJBgNVHRME
AjAAMBEGCWCGSAGG+EIBAQQEAwIFoDALBgNVHQ8EBAMCBeAwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwHQYDVR0OBBYEFCChh0rPs/Z0Lvf8b/8aIWKub5FqMB8GA1UdIwQY
MBaAFIBQXorJH3XQ5ZfnCS0zDdRHRMh0MA0GCSqGSIb3DQEBCwUAA4ICAQDHIJfK
BbHhtQyp9d08qm58+BgmuKT+ih5lCBvTReKADb2AzER5ndCTxtCo6LAG/ZRCDCQk
jkHVFDEQdkDk7+BSHgWX0DMxS7bJMCYMD8NddVsidvttxvkunoOucjElCl8VCnNR
t49dr30XwZS1fIADpnbyhXiaavxdPQ0PxVKK6bjvzqS0dRHFnHMnkC6+6kj3cI3b
eQP3GwFyZOpJdj9IgxuYhKl7zJd4EMOU2frMAiDu2vj5BIKTjjPhkxaQVDKI0bKw
/zijtnwyb/FNW5SFQ1v94Rp8pzmroGoBOvI3XqMczZeTZq8ZaJwz+OsoqEgbDHZd
w+7k0Y3Hd8Zf/QtBMlwZTbcmExJc9PlYzsxYH6n+HMMRMUncS+PYuUEfrUzoIOzY
Xxhz4lWVrr3evJMI5IVhWIHgZOAkdvOzfMUwTsj89wcRJYLrWmCE3bscNyJBpZBR
AOZ9T4juS6rcRgLN7HLZqm5cMTpsf3ampbYMSjF3kyqkiV4CgtUzY6xuTjLTizT2
ecvdUMr5qFInpaIK8JECp3lOYxBXSfXsM5J/95YY9UgHoa2nMlhcimAPkChdITJQ
aez7jiHh2lCeC0/MN4o9XXdYaEqOWzsGi/g/VQd+pXQO9GtHeOub3X8ku8xy5hZc
CazhEVmpFyKMwdD2nMNBGqSq3B6ph3jAvKHvdw==
-----END CERTIFICATE-----`}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, s := range tt.configMaps {
				indexer.Add(s)
			}
			configMapsLister := corev1listers.NewConfigMapLister(indexer)

			got := validateConfigMap(configMapsLister, tt.src)
			gotAggr := errors.NewAggregate(got)
			wantAggr := errors.NewAggregate(tt.want)
			if gotAggr != nil && wantAggr != nil {
				if gotAggr.Error() != wantAggr.Error() {
					t.Errorf("validateConfigMap() = %v, want %v", got, tt.want)
				}
			} else if gotAggr != nil || wantAggr != nil { // one of them is nil but not both
				t.Errorf("validateConfigMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ValidateServerCert(t *testing.T) {
	tests := [...]struct {
		name       string
		pem        []byte
		wantErrors []string
	}{
		{
			name: "valid",
			pem: []byte(`
-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIUUcmiUJ9GgRzK3/rqdJV0KQmC7XgwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMeHhpYV90ZXN0X2NhMCAXDTIyMDIyMzE3MDk1NVoYDzIy
OTUxMjA5MTcwOTU1WjBmMQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8w
DQYDVQQHDAZCZXJsaW4xFTATBgNVBAoMDFJlZCBIYXQgSW5jLjEeMBwGA1UEAwwV
b3BlbnNoaWZ0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvqCrAjysKeeEdnO89UfbRAqsv9PJTW+3RuulMBtdO+/OfWOIps9tHpJK
oa0EQsk4A2d8FWpEsjbUDZ+q1OEILBqYigvnmAZXTADC/fAi2bkMjOk7bytAkCPB
MYPH/8ziprbk3IP9ScfHFaiNN7WHaGVQ+qMaW1OL8oTwls7vRULYenc43KEj+jxH
bR4zNcu5h6StorzKoahsAp2oBqkdhGfTlxD0AjQo4J4MQisN3Y7OUv0kATlHi0Ip
OzqgAnl3xC1SP0XMAJIsEoCCEKlXibOlGTYe6Ib9neXHrS9X3FeUA3cfdlEWZZBu
6DMQ64S9s7GqqQGPhFfnh+XOmADC3wIDAQABoyQwIjAgBgNVHREEGTAXghVvcGVu
c2hpZnQuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAFqu/mDLAAXXzoDy
l3n7AvMeyBbZgdsKVKYlrhIkeTuB8r3AsCNPw8TcGENXizxENp72A4mFHDq1LHUf
LfMx4f4OBX2NdaHzLABZxn4+I2oRxUfWIP2sn/KVZeyU5Zl1sFzewbbpvnBr5Efb
LZTWOLgtg2zLe29drO2jqiCjLXeDexTKJQ2yW/IticVo6PAQK3r62k0TWk7lmUru
Thyplz8NFxLqi2RLOy7MD+5AbRd0LBqyCwGrsFdewZmYoumoQYv7OCLk9fyTcTBU
HDyCPQHci0vCS0EjJQbp/YfHqZc93Y/G2Y6aQaXmpS/db2W0mI9fTzVK6u4gszpL
Rur2sSg=
-----END CERTIFICATE-----`),
			wantErrors: nil,
		},
		{
			name: "missing SAN",
			pem: []byte(`
-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUdLdLqT7oG1+FhoPS114k+2+xwRcwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNb3BlbnNoaWZ0LWNhbzAgFw0yMjAyMjMxNTIyMjFaGA8y
Mjk1MTIwOTE1MjIyMVowIjEgMB4GA1UEAwwXKi5vcGVuc2hpZnQuZXhhbXBsZS5j
b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr1iZlK3kdQYzP73yz
SOMGanEylYPGLFp5i6dD1ExyCpBB+IagNMij5AMOknD7hp+oIFnM9GPWceYdVwDx
QErQDN3av+YxqnA8rGjNPJxEw9/tDDnvAGhBQK+2X70IdMeQspB+JSPkNapg3muq
TU681N2wsWp5EI1lj9bG346gLfKcdHaEeXzDfuOmVDpuYGLG+0gMNusOKVfF5ihL
o15TW7T6MwI1/pDlNt463eyHYuM3tu8KFbXq7XbmV3BviSdyK7Ia8IIz5/6R5SKE
v+FLtidFR+NaTLoRWeKTME08zn10kLKjRqu9vtVw4Fvfq4hevWOa3lPYCq1LxoAO
CX5HAgMBAAGjOTA3MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAoheWZyf+nVIS
C7XQaXVyGI6BOhVxga5nmO40e3ywwiPgvmcE/RgFiC7+rkMUizFxaVUYjTIOWicm
DjFmx9/KZmZK093u7syr4xqkZxk/+FqCAC5HCdPU6M0PMD1RLSqo2i/m4Fv5DE5f
UMIoyY8l8oenD56JeA4HcXra90nlL63fn6Ia10loddAJYcvnl/LOpsP5Y0PVcFej
39CuE2O2WHO+EzlP+G3CbyUL8ATJdWijNV9BxBb9JPpRpmgsArDDtN6/XbvWIX2/
jPZjABsOlvj9Zk166y1gPrO1H10wWjyh8Lzd52vSRxUYSKUYpsb9m0h4vKgC7Ni2
vehFLurhTg==
-----END CERTIFICATE-----`),
			wantErrors: []string{"certificate relies on legacy Common Name field, use SANs instead"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateServerCert(tt.pem)
			if len(got) != len(tt.wantErrors) {
				t.Errorf("ValidateServerCert() = %v, want %v", got, tt.wantErrors)
			} else {
				for i := range got {
					if have, want := got[i].Error(), tt.wantErrors[i]; !strings.Contains(have, want) {
						t.Errorf("ValidateServerCert() errs[%d] = %v, want %v", i, have, want)
					}
				}
			}
		})
	}

}

func testSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-config",
		},
		Data: data,
	}
}

func testConfigMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-config",
		},
		Data: data,
	}
}
