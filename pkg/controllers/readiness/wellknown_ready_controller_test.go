package readiness

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

type testServer struct {
	sendData      []byte
	sendStatus    int
	responseDelay time.Duration
}

func (trt *testServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if trt.responseDelay > 0 {
		time.Sleep(trt.responseDelay)
	}

	w.WriteHeader(trt.sendStatus)
	w.Write(trt.sendData)
}

type testRoundTripper struct {
	failTimes int
	err       error

	failCounter int

	delegate *http.Transport
}

func (trt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if trt.failCounter < trt.failTimes {
		trt.failCounter++
		return nil, trt.err
	}

	return trt.delegate.RoundTrip(req)
}

func Test_wellKnownReadyController_checkWellknownEndpointReady(t *testing.T) {

	tests := []struct {
		name             string
		cmOAuthData      string
		testServerConfig *testServer
		testRoundTripper *testRoundTripper
		wantErr          bool
	}{
		{
			name:        "wellknown endpoint not found",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				sendStatus: http.StatusNotFound,
			},
			wantErr: true,
		},
		{
			name:        "wellknown endpoint data is stale",
			cmOAuthData: `{"data": "new data"}`,
			testServerConfig: &testServer{
				sendStatus: http.StatusOK,
				sendData:   []byte(`{"data": "old data"}`),
			},
			wantErr: true,
		},
		{
			name:        "everything's fine",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				sendStatus: http.StatusOK,
				sendData:   []byte(`{"data": "some data"}`),
			},
			wantErr: false,
		},
		{
			name:        "wellknown endpoint is intermittently unavailable",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				sendStatus: http.StatusOK,
				sendData:   []byte(`{"data": "some data"}`),
			},
			testRoundTripper: &testRoundTripper{
				failTimes: 2,
				err:       net.Error(&net.DNSError{}),
			},
			wantErr: false,
		},
		{
			name:        "wellknown endpoint request always fails",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				sendStatus: http.StatusOK,
				sendData:   []byte(`{"data": "some data"}`),
			},
			testRoundTripper: &testRoundTripper{
				failTimes: 100,
				err:       net.Error(&net.DNSError{}),
			},
			wantErr: true,
		},
		{
			name:        "wellknown endpoint response takes too long",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				responseDelay: 7 * time.Second,
				sendStatus:    http.StatusOK,
				sendData:      []byte(`{"data": "some data"}`),
			},
			wantErr: true,
		},
		{
			name:        "wellknown endpoint response is slightly delayed",
			cmOAuthData: `{"data": "some data"}`,
			testServerConfig: &testServer{
				responseDelay: 3 * time.Second,
				sendStatus:    http.StatusOK,
				sendData:      []byte(`{"data": "some data"}`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oauth-openshift",
					Namespace: "openshift-config-managed",
				},
				Data: map[string]string{
					"oauthMetadata": tt.cmOAuthData,
				},
			}
			s := httptest.NewTLSServer(tt.testServerConfig)
			defer s.Close()
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(s.Certificate())

			cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, cmIndexer.Add(cm))

			c := &wellKnownReadyController{
				configMapLister: corev1listers.NewConfigMapLister(cmIndexer),
			}

			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig.RootCAs = rootCAs
			rt := http.RoundTripper(transport)
			if tt.testRoundTripper != nil {
				tt.testRoundTripper.delegate = transport
				rt = tt.testRoundTripper
			}

			testURL, err := url.Parse(s.URL)
			require.NoError(t, err)

			testCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.checkWellknownEndpointReady(testCtx, testURL.Host, rt); (err != nil) != tt.wantErr {
				t.Errorf("wellKnownReadyController.checkWellknownEndpointReady() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type fakeCADataGetter struct {
	caData []byte
	err    error
}

func (f *fakeCADataGetter) GetCAData() ([]byte, error) {
	return f.caData, f.err
}

type serverResponse struct {
	status int
	body   []byte
}

type sequentialHandler struct {
	mu        sync.Mutex
	responses []serverResponse
	idx       int
}

func (h *sequentialHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	resp := h.responses[h.idx]
	h.idx++
	h.mu.Unlock()
	w.WriteHeader(resp.status)
	w.Write(resp.body)
}

func generateTestCACert(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	return caPEM, caCert, caKey
}

func generateTestServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kubernetes.default.svc"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"kubernetes.default.svc"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}
}

func newTestTLSServer(t *testing.T, handler http.Handler, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	serverCert := generateTestServerCert(t, caCert, caKey)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	return server
}

func buildKubernetesServiceAndEndpoints(t *testing.T, targetPort int, numEndpoints int) (*corev1.Service, *discoveryv1.EndpointSlice) {
	t.Helper()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       int32(kasServicePort),
					TargetPort: intstr.FromInt(targetPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	ready := true
	endpoints := make([]discoveryv1.Endpoint, numEndpoints)
	for i := range endpoints {
		endpoints[i] = discoveryv1.Endpoint{
			Addresses:  []string{"127.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}
	}

	port := int32(targetPort)
	protocol := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-abcde",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "kubernetes"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports: []discoveryv1.EndpointPort{
			{
				Port:     &port,
				Protocol: &protocol,
			},
		},
	}

	return svc, slice
}

// kasEndpointSlice builds an EndpointSlice for the kubernetes service of the
// given address family, advertising a single port and the provided endpoints.
func kasEndpointSlice(name string, addressType discoveryv1.AddressType, port *int32, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "kubernetes"},
		},
		AddressType: addressType,
		Endpoints:   endpoints,
		Ports: []discoveryv1.EndpointPort{
			{Port: port, Protocol: ptr.To(corev1.ProtocolTCP)},
		},
	}
}

func Test_getAPIServerIPs(t *testing.T) {
	const targetPort = 6443
	svc, _ := buildKubernetesServiceAndEndpoints(t, targetPort, 0)

	readyEndpoint := func(address string) discoveryv1.Endpoint {
		return discoveryv1.Endpoint{
			Addresses:  []string{address},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}
	}

	tests := []struct {
		name    string
		slices  []*discoveryv1.EndpointSlice
		want    []string
		wantErr bool
	}{
		{
			// Dual-stack: ready backends split across an IPv4 and an IPv6 slice
			// must all be aggregated into the result.
			name: "ready backends aggregated across two slices",
			slices: []*discoveryv1.EndpointSlice{
				kasEndpointSlice("kubernetes-ipv4", discoveryv1.AddressTypeIPv4, ptr.To(int32(targetPort)), readyEndpoint("10.0.0.1")),
				kasEndpointSlice("kubernetes-ipv6", discoveryv1.AddressTypeIPv6, ptr.To(int32(targetPort)), readyEndpoint("fd00::1")),
			},
			want: []string{
				net.JoinHostPort("10.0.0.1", strconv.Itoa(targetPort)),
				net.JoinHostPort("fd00::1", strconv.Itoa(targetPort)),
			},
		},
		{
			// A not-ready backend on the target port means the backends are not
			// all ready, mirroring the previous Endpoints behavior.
			name: "unready backend on target port fails readiness",
			slices: []*discoveryv1.EndpointSlice{
				kasEndpointSlice("kubernetes-ipv4", discoveryv1.AddressTypeIPv4, ptr.To(int32(targetPort)),
					readyEndpoint("10.0.0.1"),
					discoveryv1.Endpoint{
						Addresses:  []string{"10.0.0.2"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
					},
				),
			},
			wantErr: true,
		},
		{
			// A slice that advertises only a non-target port is ignored, leaving
			// no matching backend.
			name: "slice without target port is not matched",
			slices: []*discoveryv1.EndpointSlice{
				kasEndpointSlice("kubernetes-ipv4", discoveryv1.AddressTypeIPv4, ptr.To(int32(9999)), readyEndpoint("10.0.0.1")),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, svcIndexer.Add(svc))
			sliceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, slice := range tt.slices {
				require.NoError(t, sliceIndexer.Add(slice))
			}

			c := &wellKnownReadyController{
				serviceLister:        corev1listers.NewServiceLister(svcIndexer),
				endpointSlicesLister: discoveryv1listers.NewEndpointSliceLister(sliceIndexer),
			}

			got, err := c.getAPIServerIPs()
			if (err != nil) != tt.wantErr {
				t.Fatalf("getAPIServerIPs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func Test_wellKnownReadyController_isWellknownEndpointsReady(t *testing.T) {
	matchingMetadata := `{"issuer":"https://example.com"}`
	staleMetadata := `{"issuer":"https://stale.example.com"}`

	tests := []struct {
		name              string
		authConfig        *configv1.Authentication
		oauthMetadata     string
		serverResponses   []serverResponse
		expectAvailable   bool
		expectErr         bool
		expectDegradation bool
	}{
		{
			name: "auth type not operator-managed skips checks",
			authConfig: &configv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.AuthenticationSpec{
					OAuthMetadata: configv1.ConfigMapNameReference{
						Name: "custom-metadata",
					},
				},
			},
			expectAvailable:   true,
			expectErr:         false,
			expectDegradation: false,
		},
		{
			name:          "all endpoints healthy",
			oauthMetadata: matchingMetadata,
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			expectAvailable:   true,
			expectErr:         false,
			expectDegradation: false,
		},
		{
			name:          "one endpoint returns 404 others healthy",
			oauthMetadata: matchingMetadata,
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusNotFound},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			expectAvailable:   true,
			expectErr:         true,
			expectDegradation: true,
		},
		{
			name:          "all endpoints return 404",
			oauthMetadata: matchingMetadata,
			serverResponses: []serverResponse{
				{status: http.StatusNotFound},
				{status: http.StatusNotFound},
				{status: http.StatusNotFound},
			},
			expectAvailable:   false,
			expectErr:         true,
			expectDegradation: false,
		},
		{
			name:          "single endpoint returns 404",
			oauthMetadata: matchingMetadata,
			serverResponses: []serverResponse{
				{status: http.StatusNotFound},
			},
			expectAvailable:   false,
			expectErr:         true,
			expectDegradation: false,
		},
		{
			name:          "one endpoint returns stale metadata others healthy",
			oauthMetadata: matchingMetadata,
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusOK, body: []byte(staleMetadata)},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			expectAvailable:   true,
			expectErr:         true,
			expectDegradation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authConfig == nil {
				tt.authConfig = &configv1.Authentication{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec: configv1.AuthenticationSpec{
						Type: configv1.AuthenticationTypeIntegratedOAuth,
					},
				}
			}

			c := &wellKnownReadyController{}

			if tt.serverResponses != nil {
				caPEM, caCert, caKey := generateTestCACert(t)

				handler := &sequentialHandler{responses: tt.serverResponses}
				server := newTestTLSServer(t, handler, caCert, caKey)
				defer server.Close()

				serverURL, err := url.Parse(server.URL)
				require.NoError(t, err)
				_, portStr, err := net.SplitHostPort(serverURL.Host)
				require.NoError(t, err)
				port, err := strconv.Atoi(portStr)
				require.NoError(t, err)

				origKASPort := kasServicePort
				kasServicePort = port
				defer func() { kasServicePort = origKASPort }()

				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-openshift",
						Namespace: "openshift-config-managed",
					},
					Data: map[string]string{
						"oauthMetadata": tt.oauthMetadata,
					},
				}

				svc, slice := buildKubernetesServiceAndEndpoints(t, port, len(tt.serverResponses))

				cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, cmIndexer.Add(cm))

				svcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, svcIndexer.Add(svc))

				sliceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, sliceIndexer.Add(slice))

				c.caDataGetter = &fakeCADataGetter{caData: caPEM}
				c.configMapLister = corev1listers.NewConfigMapLister(cmIndexer)
				c.serviceLister = corev1listers.NewServiceLister(svcIndexer)
				c.endpointSlicesLister = discoveryv1listers.NewEndpointSliceLister(sliceIndexer)
			}

			ctx := context.Background()
			avail, err := c.isWellknownEndpointsReady(ctx, &operatorv1.OperatorSpec{}, tt.authConfig, &configv1.Infrastructure{})

			if avail != tt.expectAvailable {
				t.Errorf("available = %v, want %v", avail, tt.expectAvailable)
			}
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, wantErr %v", err, tt.expectErr)
			}
			if tt.expectDegradation {
				if _, ok := err.(*ControllerDegradationObservedError); !ok {
					t.Errorf("expected *ControllerDegradationObservedError, got %T: %v", err, err)
				}
			} else {
				if _, ok := err.(*ControllerDegradationObservedError); ok {
					t.Errorf("expected plain error, got *ControllerDegradationObservedError: %v", err)
				}
			}
		})
	}
}

type fakeOIDCAvailabler struct {
	available bool
	err       error
}

func (f *fakeOIDCAvailabler) OIDCAvailable() (bool, error) {
	return f.available, f.err
}

func Test_wellKnownReadyController_sync(t *testing.T) {
	matchingMetadata := `{"issuer":"https://example.com"}`

	degradationObservedConditionName := ControllerDegradationObservedConditionName(controllerName)

	tests := []struct {
		name                    string
		serverResponses         []serverResponse
		seedDegradationTimeout  bool
		expectSyncErr           bool
		expectAvailableStatus   operatorv1.ConditionStatus
		expectAvailableReason   string
		expectDegradationStatus operatorv1.ConditionStatus
	}{
		{
			name: "all endpoints healthy",
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			expectSyncErr:           false,
			expectAvailableStatus:   operatorv1.ConditionTrue,
			expectAvailableReason:   "AsExpected",
			expectDegradationStatus: operatorv1.ConditionFalse,
		},
		{
			name: "partial failure sets available true and degradation observed",
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusNotFound},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			expectSyncErr:           false,
			expectAvailableStatus:   operatorv1.ConditionTrue,
			expectAvailableReason:   "AtLeastOneWellKnownEndpointAvailable",
			expectDegradationStatus: operatorv1.ConditionTrue,
		},
		{
			name: "total failure sets available false and returns error",
			serverResponses: []serverResponse{
				{status: http.StatusNotFound},
				{status: http.StatusNotFound},
				{status: http.StatusNotFound},
			},
			expectSyncErr:           true,
			expectAvailableStatus:   operatorv1.ConditionFalse,
			expectAvailableReason:   "NotReady",
			expectDegradationStatus: operatorv1.ConditionTrue,
		},
		{
			name: "partial failure with degradation timeout exceeded returns error",
			serverResponses: []serverResponse{
				{status: http.StatusOK, body: []byte(matchingMetadata)},
				{status: http.StatusNotFound},
				{status: http.StatusOK, body: []byte(matchingMetadata)},
			},
			seedDegradationTimeout:  true,
			expectSyncErr:           true,
			expectAvailableStatus:   operatorv1.ConditionTrue,
			expectAvailableReason:   "AtLeastOneWellKnownEndpointAvailable",
			expectDegradationStatus: operatorv1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caPEM, caCert, caKey := generateTestCACert(t)

			handler := &sequentialHandler{responses: tt.serverResponses}
			server := newTestTLSServer(t, handler, caCert, caKey)
			defer server.Close()

			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			_, portStr, err := net.SplitHostPort(serverURL.Host)
			require.NoError(t, err)
			port, err := strconv.Atoi(portStr)
			require.NoError(t, err)

			origKASPort := kasServicePort
			kasServicePort = port
			defer func() { kasServicePort = origKASPort }()

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oauth-openshift",
					Namespace: "openshift-config-managed",
				},
				Data: map[string]string{
					"oauthMetadata": matchingMetadata,
				},
			}

			authConfig := &configv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.AuthenticationSpec{
					Type: configv1.AuthenticationTypeIntegratedOAuth,
				},
			}

			infraConfig := &configv1.Infrastructure{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			}

			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oauth-openshift",
					Namespace: "openshift-authentication",
				},
			}

			svc, slice := buildKubernetesServiceAndEndpoints(t, port, len(tt.serverResponses))

			cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, cmIndexer.Add(cm))

			svcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, svcIndexer.Add(svc))

			sliceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, sliceIndexer.Add(slice))

			authIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, authIndexer.Add(authConfig))

			infraIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, infraIndexer.Add(infraConfig))

			routeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, routeIndexer.Add(route))

			var existingConditions []operatorv1.OperatorCondition
			if tt.seedDegradationTimeout {
				wellKnown := fmt.Sprintf("https://127.0.0.1:%d/.well-known/oauth-authorization-server", port)
				expectedMsg := fmt.Sprintf(
					"kube-apiserver oauth endpoint %s is not yet served and authentication operator keeps waiting (check kube-apiserver operator, and check that instances roll out successfully, which can take several minutes per instance)",
					wellKnown,
				)
				existingConditions = []operatorv1.OperatorCondition{
					{
						Type:               degradationObservedConditionName,
						Status:             operatorv1.ConditionTrue,
						Reason:             "AtLeastOneWellKnownEndpointUnavailable",
						Message:            expectedMsg,
						LastTransitionTime: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
					},
				}
			}

			operatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{},
				&operatorv1.OperatorStatus{Conditions: existingConditions},
				nil,
			)

			c := &wellKnownReadyController{
				controllerInstanceName: "test-instance",
				operatorClient:         operatorClient,
				authLister:             configv1listers.NewAuthenticationLister(authIndexer),
				infrastructureLister:   configv1listers.NewInfrastructureLister(infraIndexer),
				routeLister:            routev1listers.NewRouteLister(routeIndexer),
				configMapLister:        corev1listers.NewConfigMapLister(cmIndexer),
				serviceLister:          corev1listers.NewServiceLister(svcIndexer),
				endpointSlicesLister:   discoveryv1listers.NewEndpointSliceLister(sliceIndexer),
				caDataGetter:           &fakeCADataGetter{caData: caPEM},
				authConfigChecker:      &fakeOIDCAvailabler{},
			}

			syncErr := c.sync(context.Background(), nil)
			if (syncErr != nil) != tt.expectSyncErr {
				t.Fatalf("sync error = %v, wantErr %v", syncErr, tt.expectSyncErr)
			}

			_, status, _, err := operatorClient.GetOperatorState()
			require.NoError(t, err)

			availableCondition := v1helpers.FindOperatorCondition(status.Conditions, "WellKnownAvailable")
			if availableCondition == nil {
				t.Fatal("WellKnownAvailable condition not found")
			}
			if availableCondition.Status != tt.expectAvailableStatus {
				t.Errorf("WellKnownAvailable status = %v, want %v", availableCondition.Status, tt.expectAvailableStatus)
			}
			if availableCondition.Reason != tt.expectAvailableReason {
				t.Errorf("WellKnownAvailable reason = %v, want %v", availableCondition.Reason, tt.expectAvailableReason)
			}

			degradationCondition := v1helpers.FindOperatorCondition(status.Conditions, degradationObservedConditionName)
			if degradationCondition == nil {
				t.Fatal("DegradationObserved condition not found")
			}
			if degradationCondition.Status != tt.expectDegradationStatus {
				t.Errorf("DegradationObserved status = %v, want %v", degradationCondition.Status, tt.expectDegradationStatus)
			}
		})
	}
}
