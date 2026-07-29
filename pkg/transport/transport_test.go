package transport

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cluster-authentication-operator/pkg/internal/transporttest"
)

func TestNewTransport(t *testing.T) {
	_, caPEM := transporttest.MakeSelfSignedCA(t)

	ca, _ := transporttest.MakeSelfSignedCA(t)
	clientCfg, err := ca.MakeClientCertificateForDuration(&user.DefaultInfo{Name: "test-client"}, time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := clientCfg.GetPEMBytes()
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock)

	checkErrorContains := func(want string) func(*testing.T, *http.Transport, error) {
		return func(t *testing.T, tr *http.Transport, err error) {
			t.Helper()
			require.ErrorContains(t, err, want)
			require.Nil(t, tr)
		}
	}

	tests := []struct {
		name       string
		serverName string
		caData     []byte
		certData   []byte
		keyData    []byte
		check      func(*testing.T, *http.Transport, error)
	}{
		{
			name: "nil caData returns transport without RootCAs",
			check: func(t *testing.T, tr *http.Transport, err error) {
				require.NoError(t, err)
				require.Nil(t, transporttest.RootCAs(t, tr))
			},
		},
		{
			name:     "cert without key returns error",
			certData: []byte("cert"),
			check:    checkErrorContains("cert and key data must be specified together"),
		},
		{
			name:    "key without cert returns error",
			keyData: []byte("key"),
			check:   checkErrorContains("cert and key data must be specified together"),
		},
		{
			name:   "valid CA configures RootCAs",
			caData: caPEM,
			check: func(t *testing.T, tr *http.Transport, err error) {
				require.NoError(t, err)
				transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), caPEM)
			},
		},
		{
			name:       "server name is propagated",
			serverName: "my-server",
			check: func(t *testing.T, tr *http.Transport, err error) {
				require.NoError(t, err)
				require.NotNil(t, tr.TLSClientConfig)
				require.Equal(t, "my-server", tr.TLSClientConfig.ServerName)
			},
		},
		{
			name:     "valid cert and key pair is loaded",
			certData: certPEM,
			keyData:  keyPEM,
			check: func(t *testing.T, tr *http.Transport, err error) {
				require.NoError(t, err)
				require.NotNil(t, tr.TLSClientConfig)
				require.Len(t, tr.TLSClientConfig.Certificates, 1)
				require.Equal(t, certBlock.Bytes, tr.TLSClientConfig.Certificates[0].Certificate[0])
			},
		},
		{
			name:     "invalid cert and key pair returns error",
			certData: []byte("bad-cert"),
			keyData:  []byte("bad-key"),
			check:    checkErrorContains("error loading x509 keypair from cert and key data"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := NewTransport(tt.serverName, tt.caData, tt.certData, tt.keyData)
			tt.check(t, tr, err)
		})
	}
}

func TestLoadCAData(t *testing.T) {
	caData := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	tests := []struct {
		name    string
		cms     []*corev1.ConfigMap
		cmName  string
		cmKey   string
		want    []byte
		wantErr string
	}{
		{
			name: "returns Data value",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": string(caData)},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   caData,
		},
		{
			name: "falls back to BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				BinaryData: map[string][]byte{"ca-bundle.crt": caData},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   caData,
		},
		{
			name: "Data takes precedence over BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "from-data"},
				BinaryData: map[string][]byte{"ca-bundle.crt": []byte("from-binary")},
			}},
			cmName: "my-ca",
			cmKey:  "ca-bundle.crt",
			want:   []byte("from-data"),
		},
		{
			name:    "configmap not found",
			cmName:  "nonexistent",
			cmKey:   "ca-bundle.crt",
			wantErr: `unable to get configmap "openshift-config/nonexistent": configmap "nonexistent" not found`,
		},
		{
			name: "key missing from both Data and BinaryData",
			cms: []*corev1.ConfigMap{{
				ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: "openshift-config"},
				Data:       map[string]string{"other-key": "value"},
			}},
			cmName:  "my-ca",
			cmKey:   "ca-bundle.crt",
			wantErr: `configmap "openshift-config/my-ca" has no CA data at key "ca-bundle.crt"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := newConfigMapLister(tt.cms...)
			got, err := LoadCAData(lister, tt.cmName, tt.cmKey)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAppendPEMCerts(t *testing.T) {
	_, ca1PEM := transporttest.MakeSelfSignedCA(t)
	_, ca2PEM := transporttest.MakeSelfSignedCA(t)

	malformedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-der-cert")})
	nonCertBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("irrelevant")})

	tests := []struct {
		name       string
		data       []byte
		wantOK     bool
		wantErr    string
		wantInPool [][]byte
	}{
		{
			name:       "valid single cert",
			data:       ca1PEM,
			wantOK:     true,
			wantInPool: [][]byte{ca1PEM},
		},
		{
			name:       "valid multiple certs",
			data:       append(ca1PEM, ca2PEM...),
			wantOK:     true,
			wantInPool: [][]byte{ca1PEM, ca2PEM},
		},
		{
			name:   "empty data",
			data:   nil,
			wantOK: false,
		},
		{
			name:   "non-CERTIFICATE block skipped",
			data:   nonCertBlock,
			wantOK: false,
		},
		{
			name:    "malformed CERTIFICATE block returns error with index",
			data:    malformedCert,
			wantErr: "failed to parse certificate at index 0",
		},
		{
			name:       "malformed cert after valid cert returns error with index and partial pool",
			data:       append(ca1PEM, malformedCert...),
			wantOK:     true,
			wantErr:    "failed to parse certificate at index 1",
			wantInPool: [][]byte{ca1PEM},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := x509.NewCertPool()
			ok, err := AppendPEMCerts(pool, tt.data)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantOK, ok)
			if len(tt.wantInPool) > 0 {
				transporttest.RequirePoolContains(t, pool, tt.wantInPool...)
			}
		})
	}
}

func newConfigMapLister(cms ...*corev1.ConfigMap) corelistersv1.ConfigMapLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, cm := range cms {
		_ = indexer.Add(cm)
	}
	return corelistersv1.NewConfigMapLister(indexer)
}
