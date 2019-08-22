package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/client-go/config/clientset/versioned"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

func TestRouterCerts(t *testing.T) {
	kubeConfig, err := e2e.NewClientConfigForTest()
	require.NoError(t, err)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)
	configClient, err := versioned.NewForConfig(kubeConfig)
	require.NoError(t, err)
	// machine managed router-certs secret should exist
	machineManagedRouterCerts, err := kubeClient.CoreV1().Secrets("openshift-config-managed").Get("router-certs", metav1.GetOptions{})
	require.NoError(t, err)
	// operator managed router-certs secret should exist
	operatorManagedRouterCerts, err := kubeClient.CoreV1().Secrets("openshift-authentication").Get("v4-0-config-system-router-certs", metav1.GetOptions{})
	require.NoError(t, err)
	// operator managed router-certs data should be a copy of machine managed router-certs
	require.Equal(t, operatorManagedRouterCerts.Data, machineManagedRouterCerts.Data)
	// there should be an entry for the ingress domain
	ingress, err := configClient.ConfigV1().Ingresses().Get("cluster", metav1.GetOptions{})
	require.NoError(t, err)
	require.Contains(t, operatorManagedRouterCerts.Data, ingress.Spec.Domain)
	// the entry should contain certificates that validate the oauth service hostname
	block, _ := pem.Decode(operatorManagedRouterCerts.Data[ingress.Spec.Domain])
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	err = cert.VerifyHostname("oauth-openshift." + ingress.Spec.Domain)
	assert.NoError(t, err)
}
