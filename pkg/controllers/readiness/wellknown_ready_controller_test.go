package readiness

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
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
