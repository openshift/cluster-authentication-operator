package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Operator][Routes][Serial] TestCustomRouterCerts", func() {
		testCustomRouterCerts(g.GinkgoTB())
	})
})

func testCustomRouterCerts(t testing.TB) {
	kubeConfig := e2e.NewClientConfigForTest(t)

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	require.NoError(t, err)
	configClient, err := configclient.NewForConfig(kubeConfig)
	require.NoError(t, err)
	routeClient, err := routeclient.NewForConfig(kubeConfig)
	require.NoError(t, err)

	// generate crypto materials
	rootCA := e2e.NewCertificateAuthorityCertificate(t, nil)
	intermediateCA := e2e.NewCertificateAuthorityCertificate(t, rootCA)
	// check that the route is set to defaults if a non-existant secret is provided
	ingressConfig, err := configClient.ConfigV1().Ingresses().Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	fooHostname := "foo." + ingressConfig.Spec.Domain
	server := e2e.NewServerCertificate(t, intermediateCA, fooHostname)

	// create tls secret
	privateKey, err := keyutil.MarshalPrivateKeyToPEM(server.PrivateKey)
	require.NoError(t, err)

	customServerCertPEM := pem.EncodeToMemory(&pem.Block{Type: cert.CertificateBlockType, Bytes: server.Certificate.Raw})

	// Generate a valid Kubernetes name from the test name
	// Replace invalid characters with hyphens and ensure it starts/ends with alphanumeric
	secretName := strings.ToLower(t.Name())
	secretName = strings.ReplaceAll(secretName, "/", "-")
	secretName = strings.ReplaceAll(secretName, " ", "-")
	secretName = strings.ReplaceAll(secretName, "[", "")
	secretName = strings.ReplaceAll(secretName, "]", "")
	secretName = strings.Trim(secretName, "-")
	if len(secretName) > 63 {
		secretName = secretName[:63]
	}
	secretName = strings.TrimRight(secretName, "-")

	secret, err := kubeClient.CoreV1().Secrets("openshift-config").Create(
		context.TODO(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{GenerateName: secretName + "-"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": customServerCertPEM,
				"tls.key": privateKey,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	defer func() {
		err = removeComponentRoute(t, configClient, "openshift-authentication", "oauth-openshift")
		require.NoError(t, err)
		err = kubeClient.CoreV1().Secrets(secret.Namespace).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	// check that the trust-distribution works by publishing the server certificate
	distributedServerCert, err := kubeClient.CoreV1().ConfigMaps("openshift-config-managed").Get(context.Background(), "oauth-serving-cert", metav1.GetOptions{})
	require.NoError(t, err)

	distributedServerCertPem := distributedServerCert.Data["ca-bundle.crt"]
	require.NotZero(t, len(distributedServerCertPem))

	// set a custom hostname without a secret
	err = getAndUpdateComponentRoute(t, configClient, &configv1.ComponentRouteSpec{
		Namespace: "openshift-authentication",
		Name:      "oauth-openshift",
		Hostname:  "foo.bar.com",
	})
	require.NoError(t, err)

	// check that the hostname was updated
	err = checkRouteHostname(t, routeClient, "openshift-authentication", "oauth-openshift", "foo.bar.com")
	require.NoError(t, err)

	// update the hostname and provide a custom secret that does not exist
	err = getAndUpdateComponentRoute(t, configClient, &configv1.ComponentRouteSpec{
		Namespace: "openshift-authentication",
		Name:      "oauth-openshift",
		Hostname:  "new.foo.bar.com",
		ServingCertKeyPairSecret: configv1.SecretNameReference{
			Name: "missing-secret",
		},
	})
	require.NoError(t, err)

	// check that the hostname of the route is not changed because a missing secret was provided
	err = checkRouteHostname(t, routeClient, "openshift-authentication", "oauth-openshift", "foo.bar.com")
	require.NoError(t, err)

	// Update the hostname and use a valid secret
	err = getAndUpdateComponentRoute(t, configClient, &configv1.ComponentRouteSpec{
		Namespace: "openshift-authentication",
		Name:      "oauth-openshift",
		Hostname:  configv1.Hostname(fooHostname),
		ServingCertKeyPairSecret: configv1.SecretNameReference{
			Name: secret.Name,
		},
	})
	require.NoError(t, err)

	waitForDistributedCert(t, kubeClient, customServerCertPEM)

	err = checkRouteHostname(t, routeClient, "openshift-authentication", "oauth-openshift", fooHostname)
	require.NoError(t, err)

	// Check that the route is serving
	err = pollForCustomServingCertificates(t, "https://"+fooHostname, server.Certificate)
	require.NoError(t, err)
}

func waitForDistributedCert(t testing.TB, kubeClient kubernetes.Interface, expectedCertPem []byte) {
	var currentCert string
	err := wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		// check that the trust-distribution works by publishing the server certificate
		distributedServerCert, err := kubeClient.CoreV1().ConfigMaps("openshift-config-managed").Get(context.Background(), "oauth-serving-cert", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to retrieve the server cert for distributed trust: %v", err)
			return false, nil
		}

		currentCert = distributedServerCert.Data["ca-bundle.crt"]
		return strings.TrimSpace(currentCert) == strings.TrimSpace(string(expectedCertPem)), nil
	})

	require.NoError(t, err, "failed to wait for the distributed cert, current certificate is %s\n != %s", currentCert, expectedCertPem)
}

func pollForCustomServingCertificates(t testing.TB, hostname string, certificate *x509.Certificate) error {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest(http.MethodGet, hostname, nil)
	if err != nil {
		return err
	}

	return wait.PollImmediate(10*time.Second, 10*time.Minute, func() (bool, error) {
		reqCtx, cancel := context.WithTimeout(context.TODO(), 10*time.Second) // avoid waiting forever
		defer cancel()
		req = req.WithContext(reqCtx)

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Logf("failed to send a HTTP request to %s: %v", hostname, err)
			return false, nil
		}
		defer resp.Body.Close()

		if numCerts := len(resp.TLS.PeerCertificates); numCerts != 1 {
			t.Logf("Unexpected number of certificates returned: Got %d, want %d", numCerts, 1)
			return false, nil
		}
		actualCert := resp.TLS.PeerCertificates[0]
		if !reflect.DeepEqual(actualCert.Subject, certificate.Subject) {
			t.Logf("Unexpected Subject: got %v, want %v", actualCert.Subject, certificate.Subject)
			return false, nil
		}

		return true, nil
	})
}

func getAndUpdateComponentRoute(t testing.TB, configClient *configclient.Clientset, componentRoute *configv1.ComponentRouteSpec) error {
	return wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		ingressConfig, err := configClient.ConfigV1().Ingresses().Get(context.TODO(), "cluster", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("Unable to retrieve ingress config: %v", err)
			return false, nil
		}
		if err != nil {
			return false, err
		}

		found := false
		for i := range ingressConfig.Spec.ComponentRoutes {
			if ingressConfig.Spec.ComponentRoutes[i].Namespace == componentRoute.Namespace &&
				ingressConfig.Spec.ComponentRoutes[i].Name == componentRoute.Name {
				ingressConfig.Spec.ComponentRoutes[i] = *componentRoute
				found = true
			}
		}
		if !found {
			ingressConfig.Spec.ComponentRoutes = append(ingressConfig.Spec.ComponentRoutes, *componentRoute)
		}

		ingressConfig, err = configClient.ConfigV1().Ingresses().Update(context.TODO(), ingressConfig, metav1.UpdateOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}

func checkRouteHostname(t testing.TB, routeClient *routeclient.Clientset, routeNamespace string, routeName string, hostname string) error {
	return wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		route, err := routeClient.RouteV1().Routes(routeNamespace).Get(context.TODO(), routeName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("Unable to retrieve route: %v", err)
			return false, nil
		}
		if err != nil {
			t.Logf("Unable to retrieve route: %v", err)
			return false, err
		}
		return route.Spec.Host == hostname, nil
	})
}

func removeComponentRoute(t testing.TB, configClient *configclient.Clientset, namespace string, name string) error {
	return wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		ingressConfig, err := configClient.ConfigV1().Ingresses().Get(context.TODO(), "cluster", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("Unable to retrieve ingress config: %v", err)
			return false, nil
		}
		if err != nil {
			return false, err
		}

		for i := range ingressConfig.Spec.ComponentRoutes {
			if ingressConfig.Spec.ComponentRoutes[i].Namespace == namespace &&
				ingressConfig.Spec.ComponentRoutes[i].Name == name {
				// remove the componentRoute
				ingressConfig.Spec.ComponentRoutes = append(ingressConfig.Spec.ComponentRoutes[:i], ingressConfig.Spec.ComponentRoutes[i+1:]...)

				// update the ingress resource
				_, err = configClient.ConfigV1().Ingresses().Update(context.TODO(), ingressConfig, metav1.UpdateOptions{})
				if err != nil {
					return false, nil
				}
				return true, nil
			}
		}
		return true, nil
	})
}
