package common

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common/fakeinformer"
	"github.com/openshift/cluster-authentication-operator/pkg/internal/transporttest"
)

func TestAuthProxyResolver_NewTransport(t *testing.T) {
	_, proxyCAPEM := transporttest.MakeSelfSignedCA(t)
	_, extraCAPEM := transporttest.MakeSelfSignedCA(t)

	proxyCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-proxy-ca", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": string(proxyCAPEM)},
	}
	idpCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-ca", Namespace: "openshift-config"},
		Data:       map[string]string{"ca.crt": string(extraCAPEM)},
	}
	authCR := &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: operatorv1.AuthenticationSpec{
			Proxy: operatorv1.AuthenticationProxyConfig{
				HTTPSProxy: "http://proxy:3128",
				TrustedCA:  operatorv1.AuthenticationConfigMapReference{Name: "my-proxy-ca"},
			},
		},
	}

	cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, cmIndexer.Add(proxyCA))
	require.NoError(t, cmIndexer.Add(idpCA))

	authIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, authIndexer.Add(authCR))

	resolver := NewAuthProxyResolver(
		&fakeinformer.Authentication{AuthLister: operatorv1listers.NewAuthenticationLister(authIndexer)},
		corelistersv1.NewConfigMapLister(cmIndexer),
		enabledGate,
	)

	t.Run("no options loads proxy CA and sets proxy function", func(t *testing.T) {
		tr, err := resolver.NewTransport()
		require.NoError(t, err)
		require.NotNil(t, tr.Proxy)

		transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), proxyCAPEM)

		proxyURL, err := tr.Proxy(&http.Request{URL: transporttest.MustParseURL(t, "https://idp.example.com")})
		require.NoError(t, err)
		require.NotNil(t, proxyURL)
		require.Equal(t, "http://proxy:3128", proxyURL.String())
	})

	t.Run("WithCA merges proxy CA with additional CA", func(t *testing.T) {
		tr, err := resolver.NewTransport(WithCA("extra-ca", extraCAPEM))
		require.NoError(t, err)
		transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), proxyCAPEM, extraCAPEM)
	})

	t.Run("WithCAFromConfigMap merges proxy CA with configmap CA", func(t *testing.T) {
		tr, err := resolver.NewTransport(WithCAFromConfigMap("idp-ca", "ca.crt"))
		require.NoError(t, err)
		transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), proxyCAPEM, extraCAPEM)
	})

	t.Run("WithCAFromConfigMap with empty name only loads proxy CA", func(t *testing.T) {
		tr, err := resolver.NewTransport(WithCAFromConfigMap("", "ca.crt"))
		require.NoError(t, err)
		pool := transporttest.RootCAs(t, tr)
		transporttest.RequirePoolContains(t, pool, proxyCAPEM)
		transporttest.RequirePoolNotContains(t, pool, extraCAPEM)
	})

	t.Run("WithCAFromConfigMap with missing configmap returns error", func(t *testing.T) {
		_, err := resolver.NewTransport(WithCAFromConfigMap("nonexistent", "ca.crt"))
		require.ErrorContains(t, err, "nonexistent")
	})

	t.Run("feature gate disabled ignores CR proxy config", func(t *testing.T) {
		disabledResolver := NewAuthProxyResolver(
			&fakeinformer.Authentication{AuthLister: operatorv1listers.NewAuthenticationLister(authIndexer)},
			corelistersv1.NewConfigMapLister(cmIndexer),
			disabledGate,
		)

		t.Setenv("HTTP_PROXY", "")
		t.Setenv("HTTPS_PROXY", "")
		t.Setenv("NO_PROXY", "")

		tr, err := disabledResolver.NewTransport()
		require.NoError(t, err)
		require.Nil(t, transporttest.RootCAs(t, tr), "proxy CA should not be loaded when gate is disabled")

		proxyURL, err := tr.Proxy(&http.Request{URL: transporttest.MustParseURL(t, "https://example.com")})
		require.NoError(t, err)
		require.Nil(t, proxyURL, "should not proxy when gate is disabled")
	})
}

func TestAuthProxyResolver_NewTransport_MultipleOptions(t *testing.T) {
	_, caPEM1 := transporttest.MakeSelfSignedCA(t)
	_, caPEM2 := transporttest.MakeSelfSignedCA(t)

	cmIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, cmIndexer.Add(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "extra-ca", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": string(caPEM2)},
	}))

	resolver := NewAuthProxyResolver(
		&fakeinformer.Authentication{AuthLister: operatorv1listers.NewAuthenticationLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}))},
		corelistersv1.NewConfigMapLister(cmIndexer),
		featuregates.NewHardcodedFeatureGateAccess(
			nil,
			[]configv1.FeatureGateName{features.FeatureGateAuthenticationComponentProxy},
		),
	)

	tr, err := resolver.NewTransport(
		WithCA("ca-1", caPEM1),
		WithCAFromConfigMap("extra-ca", "ca-bundle.crt"),
	)
	require.NoError(t, err)
	transporttest.RequirePoolContains(t, transporttest.RootCAs(t, tr), caPEM1, caPEM2)
}

func TestAuthProxyResolver_NewTransport_Errors(t *testing.T) {
	emptyCMLister := corelistersv1.NewConfigMapLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}))

	t.Run("feature gate error propagates", func(t *testing.T) {
		resolver := NewAuthProxyResolver(
			&fakeinformer.Authentication{}, emptyCMLister,
			featuregates.NewHardcodedFeatureGateAccessForTesting(nil, nil, make(chan struct{}), errors.New("not yet observed")),
		)
		_, err := resolver.NewTransport()
		require.ErrorContains(t, err, "not yet observed")
	})

	t.Run("lister error propagates", func(t *testing.T) {
		resolver := NewAuthProxyResolver(
			&fakeinformer.Authentication{AuthLister: newErrorAuthLister(errors.New("connection refused"))},
			emptyCMLister,
			enabledGate,
		)
		_, err := resolver.NewTransport()
		require.ErrorContains(t, err, "connection refused")
	})

	t.Run("missing proxy CA configmap propagates", func(t *testing.T) {
		authCR := &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: operatorv1.AuthenticationSpec{
				Proxy: operatorv1.AuthenticationProxyConfig{
					HTTPSProxy: "http://proxy:3128",
					TrustedCA:  operatorv1.AuthenticationConfigMapReference{Name: "missing-ca"},
				},
			},
		}
		authIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		require.NoError(t, authIndexer.Add(authCR))

		resolver := NewAuthProxyResolver(
			&fakeinformer.Authentication{AuthLister: operatorv1listers.NewAuthenticationLister(authIndexer)},
			emptyCMLister,
			enabledGate,
		)
		_, err := resolver.NewTransport()
		require.ErrorContains(t, err, "missing-ca")
	})
}
