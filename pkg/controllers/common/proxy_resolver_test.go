package common

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common/fakeinformer"
)

func TestAuthProxyResolver_NewTransport_Errors(t *testing.T) {
	emptyCMLister := corelistersv1.NewConfigMapLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}))

	t.Run("enabled callback error propagates", func(t *testing.T) {
		callbackErr := errors.New("not yet observed")
		resolver := NewAuthProxyResolver(
			func() (bool, error) { return false, callbackErr },
			&fakeinformer.Authentication{}, emptyCMLister,
		)
		_, err := resolver.NewTransport()
		require.ErrorIs(t, err, callbackErr)
	})

	t.Run("lister error propagates", func(t *testing.T) {
		resolver := NewAuthProxyResolver(
			enabledAuthProxy,
			&fakeinformer.Authentication{AuthLister: newErrorAuthLister(errors.New("connection refused"))},
			emptyCMLister,
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
			enabledAuthProxy,
			&fakeinformer.Authentication{AuthLister: operatorv1listers.NewAuthenticationLister(authIndexer)},
			emptyCMLister,
		)
		_, err := resolver.NewTransport()
		require.ErrorContains(t, err, "missing-ca")
	})
}

func TestNewTransport_WithoutProxyOverridesConfiguredProxy(t *testing.T) {
	emptyCMLister := corelistersv1.NewConfigMapLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}))
	proxy := ResolvedProxy{HTTPProxy: "http://proxy:3128", HTTPSProxy: "http://proxy:3128"}

	rt, err := NewTransport(emptyCMLister, proxy, WithoutProxy())
	require.NoError(t, err)

	httpTransport, ok := rt.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", rt)
	require.Nil(t, httpTransport.Proxy, "WithoutProxy() should disable the configured proxy")
}
