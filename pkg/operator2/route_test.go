package operator2

import (
	"github.com/openshift/cluster-authentication-operator/pkg/utils"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	testing2 "k8s.io/client-go/testing"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	v1 "github.com/openshift/api/route/v1"
	routefake "github.com/openshift/client-go/route/clientset/versioned/fake"
)

const appCert = `
-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUM7PWGgD9fgSOf+PBWj1wmRkzAdEwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTY2FvLXJvdXRlLXRlc3QtYXBwczAeFw0xOTA4MjYxODMw
MTVaFw0yMDA4MjUxODMwMTVaMBMxETAPBgNVBAMMCHRlc3QtYXBwMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoC9vxsHZG2rfRwB4rFLb9KQFZHDPCjrR
AAMwTQQEZ/9JvA3NMsH40wdZvh+nO+o4OyGHwanDJJFF1vhujPweK+yxuahAHsW5
OGP6cKcxDDEgVW1VLq7iMDCjnMUOZH+tTYmkh1D8vDo52EkYCRC+58pP54RA7QvS
XL80AorzVrvjM/tu0FywSUW7C3r9BNXz7H2Iadh/PsGt1JRtY1xPF5RLxoDj0xZI
YPAeCOuO923N50WBs/K7MHJDPcQdNpgxal/wb76nUfL/PGuxSO1fwc8NGRQbncFX
xPu/IKjuKMIoLgihCMoTuVKI0YrdGcmlaNXsn4JChodNfGOiIA81XQIDAQABo04w
TDALBgNVHQ8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCQYDVR0TBAIwADAd
BgNVHREEFjAUghIqLmFwcHMuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB
ALHpSkywPBp8NfOdJ9UN6stjL7hzGSGhb7apNCF/QiFlyrmFmLsjMsIYBABIghkk
bR6KhLPq3wM3g70OyfkxbFqduAlS6PGAajbHuSartEm82nHmpx0hSvESLk1eP1t4
I6baKBrf9OpA3DGBqqLXNNTduvfqgrZbUtlvfbV3qlPo7+HYVX38PdU6f+p70Rnu
zFft7QzuGrROFTnm5p642y/iKOPJZdDEPGj16Am1PPXPwIIY9u7QZJU2QaoXMBre
DtQJUekkppx1pcqrLX5x0LLqYe9B3jTgnESm8A8boMeellPUa4F6Ytuy6nt+0bK9
VOAtyK/ZxQz1E+6x7aF7qbo=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC2jCCAcKgAwIBAgIUYo4o9Mifj4iakLloJJJJVfqU3OQwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTY2FvLXJvdXRlLXRlc3QtYXBwczAeFw0xOTA4MjYxODMw
MTVaFw0yNDA3MDYxODMwMTVaMB4xHDAaBgNVBAMME2Nhby1yb3V0ZS10ZXN0LWFw
cHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLSke+yQepdHqPjziY
SkX2nsMzxPRqFGUuYJlpZS9COdTq/JFwvphaGPIfSdwcoeJzKRULuVvpkCYO83tB
7lfIohZ0zMB1yhw5hGerA8APzlucS7HhE3S2KgUtsmyTAKkgqzQXUidcIs1tdlGH
/5nZFXcuNynfMJINeQkia4LvgHsqkuM6fvFrTbvfiQeES61jkxWAt0CDXpvBnaem
xYrkERUNLbtGOUOxkL8XIj2fYb/c+mDoXvHA8LSng2fQiMFEK6iH6agtp7J6HOHr
BcGhMdFJQSwi35Wm/6aNV0Cwi0L8moRIS5nGLFOHUu8AeD+wiWDDKqi/G9cawypi
DcBXAgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEgA
/MD+oLUBQUbcrTwHWenL0s6e7yXZv/+3RLf97GzwDJJhAM9MNZmg5uG5nDsOPrdw
XXVC3iGFFy+GojpZwlaMOCo19Wnk8utys83AmqE95TKOsY8CEsf/V8EKhtowRc/r
TdCpfvkyMDV/+fg5NInLrmE58XSoUCwp+hUQ9dKzx9JUVoil1riHUFYOjohBl4Z6
LBH2IEunrROCi0AHfUy8FFRiljAANA27bX5oZsrn+V9A9/9RSFs96VXB37N52SDP
Hcz5VI0vFZ7Sc153mLjf2a4xBqI2UZKSwXWDHyq05ZbCIZfhYef9wjJhV9tEphB1
4sQoW4pPnAZx3yDTD+8=
-----END CERTIFICATE-----
`

const appKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoC9vxsHZG2rfRwB4rFLb9KQFZHDPCjrRAAMwTQQEZ/9JvA3N
MsH40wdZvh+nO+o4OyGHwanDJJFF1vhujPweK+yxuahAHsW5OGP6cKcxDDEgVW1V
Lq7iMDCjnMUOZH+tTYmkh1D8vDo52EkYCRC+58pP54RA7QvSXL80AorzVrvjM/tu
0FywSUW7C3r9BNXz7H2Iadh/PsGt1JRtY1xPF5RLxoDj0xZIYPAeCOuO923N50WB
s/K7MHJDPcQdNpgxal/wb76nUfL/PGuxSO1fwc8NGRQbncFXxPu/IKjuKMIoLgih
CMoTuVKI0YrdGcmlaNXsn4JChodNfGOiIA81XQIDAQABAoIBAFZ6ZZjjDEeuAc5+
Jae6r/66EiMwd8XpDO45yni5o3tVqkP5G3+8ko2zGTL4Obux7huWNYlLEgwK1a6B
voUkk1FZXnWBrOQwEJet+gWZbXRMjU0xUlx6k6g6ignXpLaC61fB6G4ZPeiMcrAe
ffhe7wGKCmtNzhNrX20s2HJK+6YlvEXTdlGar5GOQgjERarR9/S5Dp1QGEDWlfNF
rGABG0TXK3ckpUytjLMr066fofF6WwahDM3mDrmqhX/bAYIJ6+spkwB/NhHGTZxu
E4F2R5bQjzuikX6O343BTPMCAz/eKZYQ7wgz13UBAhDZmd5I5swyzzmJ8AU+dufQ
7RyLLgECgYEA1XfDxsKqEG5GXZHIlYpuVg8GgI8PeVYECbyV/1oAHCoB3RK089wW
DlqiNEtIBdTqoSbzJ4g10CqKTk22/sRF+2Buaoi7H/K6aTlo3XbKPZBWL/IR/q6v
v57hSUuzWpMwh/Q1Gz24YEC8XN8E5+q4bZvf4M8FiH5ouqqtxx0hoN0CgYEAwBnr
WX85GkOnQtsQJtex6aFnHgk7by3idPSQcfma3SMGXW+k+mVop3p3gtkwfJ3W9zrv
LdT6UkiAApTHWfVac+FXZAol3ykgJhoUhMw96W/oB7P8kdZXoEqfQYYoUT4cMKjj
RDPGec4Xt0hncpVhE2mXX571eex2NYW3hwZ8XoECgYBHt578rfX44zOcyBe9te5v
10h19JpcR3u/0a4LRi93Rt2talWFAFIgrG6GZyxhWTEixzU1+Nsrfr9Mo2txmHty
gulVvW4ww5nBNFp43SoBGPb70LYe/I1rMXO67kXpjj3lzzPwXQIOxHEEOqEpUYB4
wr+qhaL0QpPo8uLDXJQpuQKBgQCZOlN64Lr4kywwbLIWeYhFFeQ9lhmdVhlDNuyc
rP91EoH6N5p9zDPNGyeG7Jz7WZ9lNtIfWbmNtpy88lWNEOLkecMOXfXVamVlXvos
7wkXUZbfxhZZcYIVrlAXoN4553Pu8FfPSAkxkU1jedJiGHsFU/1VXWLqrM2hZZZ9
kpPTgQKBgQCKBECgVnBt10pqhxvvmQW2j+yZYWP6d6N7V4F3MqFZRgPLqUXZraSZ
3PS/g3Z2UfH48L2/QZH0BP/tdGubqs5KlHfQ/MzWq13w4uEbftiB6pabo2jlj9g0
CJVLSOr7xjczmzb4jndk2VshuD5HM5Jq1wfRNYhUUZqF6d05zkGxrA==
-----END RSA PRIVATE KEY-----
`

const barCert = `
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUAxuU2bIGJ+Q6VT8NwLVWTJkDu3UwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSY2FvLXJvdXRlLXRlc3QtYmFyMB4XDTE5MDgyNjE4MTk1
NFoXDTIwMDgyNTE4MTk1NFowEzERMA8GA1UEAwwIdGVzdC1iYXIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7DiKRbFHSnZzL/FhHaXMxSiVlJ6Qd3yWr
7jUc9up6PwG2Wf9Urro1lipoHBQ435516Cz1yMt2mNlSLRfnUPoYyxIhLk8ANnXc
tdyLvVW412h3VgEMgLmxEfJSehxLUe+fmZ/ZagaiUzjfS1zPBPPclyqJPjHQoWHI
V6rJ7tD3Wi1gR8ndI8OxYlytwmLq7DKwORHMvC8PrXc+CM33XFFET4ekQf943rhA
R14uIXpFraXjWquEGWOxpZHFT5NveKdfEzimQbXBvm79JAcAAqkLkxEXAzoyOx0e
uCsbMKPtpQF23EWQxh7cceyIWtAn+Z20Dp1oI7u2UvhqMHe9L381AgMBAAGjTTBL
MAsGA1UdDwQEAwIF4DATBgNVHSUEDDAKBggrBgEFBQcDATAJBgNVHRMEAjAAMBwG
A1UdEQQVMBOCESouYmFyLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQA9
Ru/7OAwwZNCsf3TJwpWwrBGPNJILPKQawl9bUJ8o/n/aYjfnnC8a9zCZ/E1tqgv5
31Q9OwSG6Ht0c0sk0y1m68enmSsGPbRvRiSf2ooE0qr8e6QsYmySSjRAkizuPCVt
Qmpni++qjkvjwQ0AYptYSOG8oOXPHg+tJnqvRo19cCkEmi5tVJZpoomAVj6IgeiH
WiFFbXXh8+yiOr5kfhfcWU+77z9B4aHDULjJXeDOc9I4hn9TBnjQZnzEkuWSz9Qg
9OIjFrlJWAHcon5kJpoPlbQ12hYD5JB7itjCoOFAb8mqWKcimkKDzm56F3r2OcK3
lei9rxbF4ipDdNSu6LNj
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC2DCCAcCgAwIBAgIUT0auFkypU9XigDpcLYlPOuNOIqMwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSY2FvLXJvdXRlLXRlc3QtYmFyMB4XDTE5MDgyNjE4MTk1
NFoXDTI0MDcwNjE4MTk1NFowHTEbMBkGA1UEAwwSY2FvLXJvdXRlLXRlc3QtYmFy
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqMeSw52EcYzym9rHsL7U
Yc4sfQf33N8ker4RiOmS1uN7y9K48zuaT9HQWaIu/1n53ozYcTBpdqWCtTVkKCi/
u9lZN+8kvIH9/cAwo2fI6Iz2a5gz1DV5PbQv9CUx0HCyGO5quFsQt+wvNGh82S0Q
j3reaoIOaniO99Uf/HmOb233p2uKUcWadCYSymB3Qivxk03WWKdzHcLWIES5LKvo
ZFIhQWFNTFzaca07v3vRph4AI+Lb8yYQ0YSZrNRnmIAiwWJnoi+lCcnVVZBtNk9F
Le58kJq0rAhbDtcggOGhJ0ekSpiVW/qIGg1yP/gBVvD5V7rcDJENpDgmdO1zOGxd
1wIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCfHAO4
Nbrh2KH9SEK/P3ExCczpJYZ+8oI3FYrMVXvSxv2edR25qWCyrVND1AMRcUGb18cO
Guf4hQhKjY9PMUyPnJzCSnhtnbUOub09kNzUTll7fShRh05EU8cFxqqQWRPzcPk0
0GxBGeqgm1bLqD6I2X46abdvHWWp9G7Sc7fnbAVeShY2xoJDkFZf6lc4cX+CZ3lN
qpOki5++xb4LCzC6iDP3m5VFMagPsA05TGmB/HZD4ZK5KKoyUsNDapqXfMCBtPVB
mNEP6I6aS+campVzyy6QRxj3lVZIbAxDzzdIpUSGAHMUbFmJtCXXnJ3E0puid+mm
X1QJDKxxVBMF54d6
-----END CERTIFICATE-----
`

const barKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuw4ikWxR0p2cy/xYR2lzMUolZSekHd8lq+41HPbqej8Btln/
VK66NZYqaBwUON+edegs9cjLdpjZUi0X51D6GMsSIS5PADZ13LXci71VuNdod1YB
DIC5sRHyUnocS1Hvn5mf2WoGolM430tczwTz3JcqiT4x0KFhyFeqye7Q91otYEfJ
3SPDsWJcrcJi6uwysDkRzLwvD613PgjN91xRRE+HpEH/eN64QEdeLiF6Ra2l41qr
hBljsaWRxU+Tb3inXxM4pkG1wb5u/SQHAAKpC5MRFwM6MjsdHrgrGzCj7aUBdtxF
kMYe3HHsiFrQJ/mdtA6daCO7tlL4ajB3vS9/NQIDAQABAoIBABW29lxbbsQ8d89W
ZAkmPLEkImMzzuGI3h6vcIsEPwQh/Fjm6bUy83r1C8c6Oz6+9u5JHa8KuFP0OoZH
pda8l8v5BwnDDni/2b7dfdTbDfB/USlJWqXQ672aj77zXgWAZYjplJzwqgR+FMQX
Q5bkxEp/Yfi8t5u4oFlZlAINL0UHiA4d0F0ajflh8hthl+ypcIHHh9Evz4WgmZOh
OP8I25f/ArRYWxpVTBdNbmZMBCQA+uBKM/R/+oJyy5xgyOeGXGVYoZqtRypTmjBf
OJw1t80LG2/hvw1t44R5/+Fp4Ex6eMfNSjb/9/A+T8+Wke5h8eMP1KQXhkoPUXib
TqLwt6ECgYEA5gkA8vl0wRlkYqS6q2nXRTPK9UXAMTAG7/74azLA2DmuZ4OU7ZtY
TPpxHL/YAzxiaYYOQvWcyrQBK1GqMNRxFLXHAOIft9w+ISSIvI5XfH5/iWKapowk
t3kBBO6xNPGvBXKPr0jiAhcaWINy5F/tW+2/+1D5FfBqjzT7sMc4o/sCgYEA0Csz
gkP0oHnYcRt60aylCi5dGUXaUa2TtjZbEKgCwOL4hX/dz9K+drF2O2IXlS9Yu6YU
ATssrnHA/+sExR5rT4IYkZB8YLPghbQ37TBPyJarVleh8z00yKE5BXyoSvfUbYnh
63hFmFJ06wnOS/wj78W2AyLe7Mk3+PU/TROY0o8CgYARDE/GshgmC3S2HtE6zPBI
T6tV/CJfQtjwxmuwviUuoS+8ujK6XU3w/oqNf+ZJbxs4CNhbvAovt6FyjW3YipYK
2+HwvdFt9eOg3y1HFCGFt3ZKP0WI3FAITO53aB03+EVpWPEvI26kiwPH1Y4ZQMa9
jmQxAvJC3vt2u41/r3QSKwKBgH+sb2wOx8OA16oPg5WDwLls1DbC6/K6deUEk3e0
w/OPgYNHeECVbbGYh/5F3FbochCs/IoAxBe9tvR/LS7EyGY8UVs99brNt//pF4AG
6HgLSMys9KwdtvjyQOnHmeRY+dWxAnoMCwswT3s0SW27GENfzJFB2t35T7YGnKtm
QI2rAoGABNZPt44amOfkgvH6901e2/sNx8F7cWEohMAIJ8BgB6jLASqpu6eFEax0
mvBpl1SwtRbIHhGTyIFzK3zNGUuKcPSDhL95zaGbBYvWG86FR4v5XCOO9U+5xI4l
J+hyJVALyXVcxEiKZKuQsZ0rpc9pixzkExWrReDCPrn1Gb+XedY=
-----END RSA PRIVATE KEY-----
`

func Test_authOperator_handleRoute(t *testing.T) {
	var routeWeightVal int32 = 100

	var tests = map[string]struct {
		ingress             *configv1.Ingress
		expectedRoute       *v1.Route
		routeStatusOnCreate *v1.RouteStatus
		routeStatusOnUpdate *v1.RouteStatus
		expectedSecret      *corev1.Secret
		objects             []runtime.Object
		routeObjects        []runtime.Object
		expectedErr         string
		expectRouteUpdate   bool
		expectRouteCreate   bool
	}{
		"create-route": {
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					Domain: "apps.example.com",
				},
			},
			expectedRoute: &v1.Route{
				ObjectMeta: utils.DefaultMetaOAuthServerResources(),
				Spec: v1.RouteSpec{
					Host: "oauth-openshift.apps.example.com",
					To: v1.RouteTargetReference{
						Kind:   "Service",
						Name:   "oauth-openshift",
						Weight: &routeWeightVal,
					},
					Port: &v1.RoutePort{
						TargetPort: intstr.FromInt(6443),
					},
					TLS: &v1.TLSConfig{
						Termination:                   v1.TLSTerminationPassthrough,
						InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
					},
					WildcardPolicy: routev1.WildcardPolicyNone,
				},
				Status: v1.RouteStatus{
					Ingress: []v1.RouteIngress{
						{
							Host: "oauth-openshift.apps.example.com",
							Conditions: []v1.RouteIngressCondition{
								{
									Type:   v1.RouteAdmitted,
									Status: corev1.ConditionTrue,
								},
							},
						},
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "v4-0-config-system-router-certs",
					Namespace: "openshift-authentication",
				},
				Data: map[string][]byte{
					"apps.example.com": []byte(appCert),
					"tls.key":          []byte(appKey),
				},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-router-certs",
						Namespace: "openshift-authentication",
					},
					Data: map[string][]byte{
						"apps.example.com": []byte(appCert),
						"tls.key":          []byte(appKey),
					},
				},
			},
			expectRouteCreate: true,
			routeStatusOnCreate: &v1.RouteStatus{
				Ingress: []v1.RouteIngress{
					{
						Host: "oauth-openshift.apps.example.com",
						Conditions: []v1.RouteIngressCondition{
							{
								Type:   v1.RouteAdmitted,
								Status: corev1.ConditionTrue,
							},
						},
					},
				},
			},
		},
		"route-exists": {
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					Domain: "apps.example.com",
				},
			},
			expectedRoute: &v1.Route{
				ObjectMeta: utils.DefaultMetaOAuthServerResources(),
				Spec: v1.RouteSpec{
					Host: "oauth-openshift.apps.example.com",
					To: v1.RouteTargetReference{
						Kind:   "Service",
						Name:   "oauth-openshift",
						Weight: &routeWeightVal,
					},
					Port: &v1.RoutePort{
						TargetPort: intstr.FromInt(6443),
					},
					TLS: &v1.TLSConfig{
						Termination:                   v1.TLSTerminationPassthrough,
						InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
					},
					WildcardPolicy: routev1.WildcardPolicyNone,
				},
				Status: v1.RouteStatus{
					Ingress: []v1.RouteIngress{
						{
							Host: "oauth-openshift.apps.example.com",
							Conditions: []v1.RouteIngressCondition{
								{
									Type:   v1.RouteAdmitted,
									Status: corev1.ConditionTrue,
								},
							},
						},
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "v4-0-config-system-router-certs",
					Namespace: "openshift-authentication",
				},
				Data: map[string][]byte{
					"apps.example.com": []byte(appCert),
					"tls.key":          []byte(appKey),
				},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-router-certs",
						Namespace: "openshift-authentication",
					},
					Data: map[string][]byte{
						"apps.example.com": []byte(appCert),
						"tls.key":          []byte(appKey),
					},
				},
			},
			routeObjects: []runtime.Object{
				&v1.Route{
					ObjectMeta: utils.DefaultMetaOAuthServerResources(),
					Spec: v1.RouteSpec{
						Host: "oauth-openshift.apps.example.com", // mimic the behavior of subdomain
						To: v1.RouteTargetReference{
							Kind:   "Service",
							Name:   "oauth-openshift",
							Weight: &routeWeightVal,
						},
						Port: &v1.RoutePort{
							TargetPort: intstr.FromInt(6443),
						},
						TLS: &v1.TLSConfig{
							Termination:                   v1.TLSTerminationPassthrough,
							InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
						},
						WildcardPolicy: routev1.WildcardPolicyNone,
					},
					Status: v1.RouteStatus{
						Ingress: []v1.RouteIngress{
							{
								Host: "oauth-openshift.apps.example.com",
								Conditions: []v1.RouteIngressCondition{
									{
										Type:   v1.RouteAdmitted,
										Status: corev1.ConditionTrue,
									},
								},
							},
						},
					},
				},
			},
		},
		"route-update": {
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					Domain: "bar.example.com",
				},
			},
			expectedRoute: &v1.Route{
				ObjectMeta: utils.DefaultMetaOAuthServerResources(),
				Spec: v1.RouteSpec{
					Host: "oauth-openshift.bar.example.com",
					To: v1.RouteTargetReference{
						Kind:   "Service",
						Name:   "oauth-openshift",
						Weight: &routeWeightVal,
					},
					Port: &v1.RoutePort{
						TargetPort: intstr.FromInt(6443),
					},
					TLS: &v1.TLSConfig{
						Termination:                   v1.TLSTerminationPassthrough,
						InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
					},
					WildcardPolicy: routev1.WildcardPolicyNone,
				},
				Status: v1.RouteStatus{
					Ingress: []v1.RouteIngress{
						{
							Host: "oauth-openshift.bar.example.com",
							Conditions: []v1.RouteIngressCondition{
								{
									Type:   v1.RouteAdmitted,
									Status: corev1.ConditionTrue,
								},
							},
						},
					},
				},
			},
			expectRouteUpdate: true,
			routeStatusOnUpdate: &v1.RouteStatus{
				Ingress: []v1.RouteIngress{
					{
						Host: "oauth-openshift.bar.example.com",
						Conditions: []v1.RouteIngressCondition{
							{
								Type:   v1.RouteAdmitted,
								Status: corev1.ConditionTrue,
							},
						},
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "v4-0-config-system-router-certs",
					Namespace: "openshift-authentication",
				},
				Data: map[string][]byte{
					"bar.example.com": []byte(barCert),
					"tls.key":         []byte(barKey),
				},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-router-certs",
						Namespace: "openshift-authentication",
					},
					Data: map[string][]byte{
						"bar.example.com": []byte(barCert),
						"tls.key":         []byte(barKey),
					},
				},
			},
			routeObjects: []runtime.Object{
				&v1.Route{
					ObjectMeta: utils.DefaultMetaOAuthServerResources(),
					Spec: v1.RouteSpec{
						Host: "oauth-openshift.apps.example.com", // mimic the behavior of subdomain
						To: v1.RouteTargetReference{
							Kind: "Service",
							Name: "oauth-openshift",
						},
						Port: &v1.RoutePort{
							TargetPort: intstr.FromInt(6443),
						},
						TLS: &v1.TLSConfig{
							Termination:                   v1.TLSTerminationPassthrough,
							InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
						},
					},
					Status: v1.RouteStatus{
						Ingress: []v1.RouteIngress{
							{
								Host: "oauth-openshift.apps.example.com",
								Conditions: []v1.RouteIngressCondition{
									{
										Type:   v1.RouteAdmitted,
										Status: corev1.ConditionTrue,
									},
								},
							},
						},
					},
				},
			},
		},
		"route-update-invalid-route": {
			ingress: &configv1.Ingress{
				Spec: configv1.IngressSpec{
					Domain: "apps.example.com",
				},
			},
			expectedRoute: &v1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oauth-openshift",
					Namespace: "openshift-authentication",
					Labels: map[string]string{
						"app": "oauth-openshift",
					},
					Annotations: map[string]string{
						"annotationToPreserve": "foo",
					},
				},
				Spec: v1.RouteSpec{
					Host: "oauth-openshift.apps.example.com",
					To: v1.RouteTargetReference{
						Kind:   "Service",
						Name:   "oauth-openshift",
						Weight: &routeWeightVal,
					},
					Port: &v1.RoutePort{
						TargetPort: intstr.FromInt(6443),
					},
					TLS: &v1.TLSConfig{
						Termination:                   v1.TLSTerminationPassthrough,
						InsecureEdgeTerminationPolicy: v1.InsecureEdgeTerminationPolicyRedirect,
					},
					WildcardPolicy: routev1.WildcardPolicyNone,
				},
				Status: v1.RouteStatus{
					Ingress: []v1.RouteIngress{
						{
							Host: "oauth-openshift.apps.example.com",
							Conditions: []v1.RouteIngressCondition{
								{
									Type:   v1.RouteAdmitted,
									Status: corev1.ConditionTrue,
								},
							},
						},
					},
				},
			},
			expectRouteUpdate: true,
			routeStatusOnUpdate: &v1.RouteStatus{
				Ingress: []v1.RouteIngress{
					{
						Host: "oauth-openshift.apps.example.com",
						Conditions: []v1.RouteIngressCondition{
							{
								Type:   v1.RouteAdmitted,
								Status: corev1.ConditionTrue,
							},
						},
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "v4-0-config-system-router-certs",
					Namespace: "openshift-authentication",
				},
				Data: map[string][]byte{
					"apps.example.com": []byte(appCert),
					"tls.key":          []byte(appKey),
				},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "v4-0-config-system-router-certs",
						Namespace: "openshift-authentication",
					},
					Data: map[string][]byte{
						"apps.example.com": []byte(appCert),
						"tls.key":          []byte(appKey),
					},
				},
			},
			routeObjects: []runtime.Object{
				&v1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-openshift",
						Namespace: "openshift-authentication",
						Labels: map[string]string{
							"app": "oauth-openshift",
						},
						Annotations: map[string]string{
							"annotationToPreserve": "foo",
						},
					},
					Spec: v1.RouteSpec{
						Host: "oauth-openshift.apps.example.com", // mimic the behavior of subdomain
						To: v1.RouteTargetReference{
							Kind: "Service",
							Name: "oauth-openshift",
						},
						Port: &v1.RoutePort{
							TargetPort: intstr.FromInt(6443),
						},
						TLS: nil, // This invalidates the route
					},
					Status: v1.RouteStatus{
						Ingress: []v1.RouteIngress{
							{
								Host: "oauth-openshift.apps.example.com",
								Conditions: []v1.RouteIngressCondition{
									{
										Type:   v1.RouteAdmitted,
										Status: corev1.ConditionTrue,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			routeClient := routefake.NewSimpleClientset(tt.routeObjects...)
			routeClient.PrependReactor("create", "routes", func(action testing2.Action) (bool, runtime.Object, error) {
				t.Logf("create route")
				create := action.(testing2.CreateAction)
				rt := create.GetObject().(*v1.Route)
				rt.Status = *tt.routeStatusOnCreate
				return true, rt, nil
			})
			routeClient.PrependReactor("update", "routes", func(action testing2.Action) (bool, runtime.Object, error) {
				t.Logf("update route")
				update := action.(testing2.UpdateAction)
				rt := update.GetObject().(*v1.Route)
				rt.Status = *tt.routeStatusOnUpdate
				return true, rt, nil
			})

			c := &authOperator{
				secrets:    client.CoreV1(),
				configMaps: client.CoreV1(),
				route:      routeClient.RouteV1().Routes("openshift-authentication"),
			}

			route, secret, _, err := c.handleRoute(tt.ingress)
			if err != nil {
				if len(tt.expectedErr) == 0 {
					t.Errorf("unexpected error %s", err)
				} else if tt.expectedErr != err.Error() {
					t.Errorf("expected error %s, got %s", tt.expectedErr, err)
				}
			} else {
				if len(tt.expectedErr) != 0 {
					t.Errorf("expected error %s, got no error", tt.expectedErr)
				}

				routeActions := routeClient.Actions()
				if tt.expectRouteCreate {
					var created bool
					for _, act := range routeActions {
						if act.GetVerb() == "create" {
							created = true
						}
					}
					if !created {
						t.Errorf("expected route creation")
					}
				}
				if tt.expectRouteUpdate {
					var updated bool
					for _, act := range routeActions {
						if act.GetVerb() == "update" {
							updated = true
						}
					}
					if !updated {
						t.Errorf("expected route creation")
					}
				}

				if !reflect.DeepEqual(tt.expectedRoute, route) {
					t.Errorf("expected route %#v, got %#v", tt.expectedRoute, route)
				}
				if !reflect.DeepEqual(tt.expectedSecret, secret) {
					t.Errorf("handleConfigSync() secrets got = %v, want %v", secret, tt.expectedSecret)
				}
			}
		})
	}
}
