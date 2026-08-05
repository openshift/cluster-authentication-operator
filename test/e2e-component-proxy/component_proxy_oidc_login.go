package component_proxy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest/challengehandlers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Serial][Operator][ComponentProxy] should set partial and full env vars when configured", func() {
		testPartialFullProxyEnvVars()
	})
	g.It("[Serial][Operator][ComponentProxy] should apply proxy config and perform full OIDC login flow", func() {
		testProxyOIDCLoginFlow()
	})
	g.It("[Serial][Operator][ComponentProxy] should hot-reload mounted CA file on change when spec.proxy.trustedCA is set", func() {
		testTrustedCAHotReload()
	})
	g.It("[Serial][Operator][ComponentProxy] should bypass proxy for noProxy hosts", func() {
		testNoProxy()
	})
})

func testPartialFullProxyEnvVars() {
	ctx := context.Background()
	t := g.GinkgoTB()
	clients := test.NewTestClients(t)

	test.CheckFeatureGateEnabledOrSkip(t, clients.ConfigClient, features.FeatureGateAuthenticationComponentProxy)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deploying Squid forward proxy")
	httpProxyURL, httpsProxyURL, caPEM, _, proxyCleanup := test.DeploySquidProxy(t, clients.KubeClient)
	g.DeferCleanup(proxyCleanup)

	g.By("Saving original proxy config")
	operatorAuth, proxyConfigCleanup := test.SaveAndRestoreProxyConfig(t, clients.OperatorClient, clients.ConfigClient)
	g.DeferCleanup(proxyConfigCleanup)

	g.By("Setting only httpsProxy in component proxy config")
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: httpProxyURL,
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy config")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Verifying oauth-server has HTTPS_PROXY but not HTTP_PROXY")
	test.VerifyOAuthServerDeploymentProxyConfig(t, clients.KubeClient, "", httpProxyURL, ".cluster.local,.svc,127.0.0.1,localhost", false)

	configMapName := "e2e-proxy-trusted-ca"
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: "openshift-config",
		},
		Data: map[string]string{
			"ca-bundle.crt": string(caPEM),
		},
	}
	_, err = clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Create(ctx, caConfigMap, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "should be able to create trustedCA ConfigMap")
	g.DeferCleanup(func() {
		if err := clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Delete(ctx, configMapName, metav1.DeleteOptions{}); err != nil {
			g.GinkgoWriter.Printf("failed to clean up ConfigMap %s: %v\n", configMapName, err)
		}
	})

	noProxyHost := "noproxy.example.com"

	operatorAuth, err = clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Setting httpProxy, httpsProxy, noProxy, and trustedCA in component proxy config")
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPProxy:  httpProxyURL,
		HTTPSProxy: httpsProxyURL,
		NoProxy:    []string{noProxyHost},
		TrustedCA: operatorv1.AuthenticationConfigMapReference{
			Name: configMapName,
		},
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy config")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Verifying oauth-server has HTTP_PROXY, HTTPS_PROXY, and NO_PROXY with custom entry")
	test.VerifyOAuthServerDeploymentProxyConfig(t, clients.KubeClient, httpProxyURL, httpsProxyURL, ".cluster.local,.svc,127.0.0.1,localhost,noproxy.example.com", true)
}

func testProxyOIDCLoginFlow() {
	ctx := context.Background()
	t := g.GinkgoTB()
	kubeConfig := test.NewClientConfigForTest(t)
	clients := test.NewTestClients(t)

	test.CheckFeatureGateEnabledOrSkip(t, clients.ConfigClient, features.FeatureGateAuthenticationComponentProxy)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deploying Squid forward proxy")
	httpProxyURL, _, _, proxyNamespace, proxyCleanup := test.DeploySquidProxy(t, clients.KubeClient)
	g.DeferCleanup(proxyCleanup)

	g.By("Deploying Keycloak (without registering IdP yet)")
	setup := test.DeployKeycloak(t, kubeConfig)
	keycloakCleanups := setup.Cleanups
	g.DeferCleanup(test.IDPCleanupWrapper(func() {
		g.GinkgoWriter.Println("cleaning up: removing Keycloak and IdP")
		for _, cleanup := range keycloakCleanups {
			cleanup()
		}
	}))

	kcClient := setup.Client

	g.By("Enabling Direct Access Grants on Keycloak client for ROPC flow")
	enableDirectAccessGrants(kcClient, setup.ClientID)

	g.By("Deploying NetworkPolicy to restrict Keycloak ingress to proxy namespace only")
	keycloakNamespace := setup.Namespace
	networkPolicyCleanup := test.DeployProxyNetworkPolicies(t, clients.KubeClient, proxyNamespace, keycloakNamespace)
	g.DeferCleanup(func() {
		g.GinkgoWriter.Println("cleaning up: removing proxy NetworkPolicies")
		networkPolicyCleanup()
	})

	g.By("Saving original proxy config and setting component-scoped proxy")
	operatorAuth, proxyConfigCleanup := test.SaveAndRestoreProxyConfig(t, clients.OperatorClient, clients.ConfigClient)
	g.DeferCleanup(proxyConfigCleanup)

	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: httpProxyURL,
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy config")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Registering Keycloak as OIDC IdP (operator discovers it through the proxy)")
	idpCleans := test.AddKeycloakOIDCIdP(t, kubeConfig, setup, false)
	keycloakCleanups = append(keycloakCleanups, idpCleans...)

	g.By("Creating Keycloak test user and group")
	group := "ocp-test-proxy-login-group"
	o.Expect(kcClient.CreateGroup(group)).To(o.Succeed())

	username := "proxy-login-test-user"
	password := "proxy-login-test-password"
	o.Expect(kcClient.CreateUser(username, "", password, []string{group}, nil)).To(o.Succeed())

	logCutOff := time.Now()

	g.By("Performing full OIDC login flow through component proxy")
	assertOIDCLogin(t, kubeConfig, *clients, username, password, group)

	g.By("Verifying traffic went through the Squid proxy")

	issuerURL, err := url.Parse(kcClient.IssuerURL())
	o.Expect(err).NotTo(o.HaveOccurred())
	keycloakHost := issuerURL.Hostname()

	g.By("Waiting for squid logs to settle before checking for proxy traffic")
	time.Sleep(2 * time.Minute)

	logs, err := test.GetSquidProxyLogsSince(clients.KubeClient, proxyNamespace, logCutOff)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(logs).To(o.ContainSubstring(keycloakHost), "squid logs should contain keycloak traffic after proxy login")

	g.By("Creating Keycloak test user and group")
	group1 := "ocp-test-direct-fallback-group"
	o.Expect(kcClient.CreateGroup(group1)).To(o.Succeed())

	username1 := "direct-fallback-test-user"
	password1 := "direct-fallback-test-password"
	o.Expect(kcClient.CreateUser(username1, "", password1, []string{group1}, nil)).To(o.Succeed())

	g.By("Removing component-scoped proxy config")
	operatorAuth, err = clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy removal")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	logCutoff := time.Now()

	g.By("Performing OIDC login flow via direct IdP connectivity after proxy removal")
	assertOIDCLogin(t, kubeConfig, *clients, username1, password1, group1)

	g.By("Waiting for squid logs to settle before checking for absence of proxy traffic")
	time.Sleep(2 * time.Minute)

	postRemovalLogs, err := test.GetSquidProxyLogsSince(clients.KubeClient, proxyNamespace, logCutoff)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(postRemovalLogs).NotTo(o.ContainSubstring(keycloakHost), "squid logs after proxy removal should not contain keycloak connect")
}

func testTrustedCAHotReload() {
	ctx := context.Background()
	t := g.GinkgoTB()
	kubeConfig := test.NewClientConfigForTest(t)
	clients := test.NewTestClients(t)

	test.CheckFeatureGateEnabledOrSkip(t, clients.ConfigClient, features.FeatureGateAuthenticationComponentProxy)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deploying Squid forward proxy")
	_, httpsProxyURL, caFile, proxyNamespace, proxyCleanup := test.DeploySquidProxy(t, clients.KubeClient)
	g.DeferCleanup(proxyCleanup)

	g.By("Saving original proxy config")
	operatorAuth, proxyConfigCleanup := test.SaveAndRestoreProxyConfig(t, clients.OperatorClient, clients.ConfigClient)
	g.DeferCleanup(proxyConfigCleanup)

	g.By("Deploying Keycloak (without registering IdP yet)")
	setup := test.DeployKeycloak(t, kubeConfig)
	keycloakCleanups := setup.Cleanups
	g.DeferCleanup(test.IDPCleanupWrapper(func() {
		g.GinkgoWriter.Println("cleaning up: removing Keycloak and IdP")
		for _, cleanup := range keycloakCleanups {
			cleanup()
		}
	}))

	kcClient := setup.Client

	g.By("Enabling Direct Access Grants on Keycloak client for ROPC flow")
	enableDirectAccessGrants(kcClient, setup.ClientID)

	g.By("Deploying NetworkPolicy to restrict Keycloak ingress to proxy namespace only")
	keycloakNamespace := setup.Namespace
	networkPolicyCleanup := test.DeployProxyNetworkPolicies(t, clients.KubeClient, proxyNamespace, keycloakNamespace)
	g.DeferCleanup(func() {
		g.GinkgoWriter.Println("cleaning up: removing proxy NetworkPolicies")
		networkPolicyCleanup()
	})

	g.By("Creating config map with trustedCA")
	configMapName := "e2e-proxy-trusted-ca"
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: "openshift-config",
		},
		Data: map[string]string{
			"ca-bundle.crt": string(caFile),
		},
	}
	_, err = clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Create(ctx, caConfigMap, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "should be able to create trustedCA ConfigMap")
	g.DeferCleanup(func() {
		if err := clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Delete(ctx, configMapName, metav1.DeleteOptions{}); err != nil {
			g.GinkgoWriter.Printf("failed to clean up ConfigMap %s: %v\n", configMapName, err)
		}
	})

	g.By("Setting component-scoped proxy with trustedCA")
	operatorAuth, err = clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: httpsProxyURL,
		TrustedCA: operatorv1.AuthenticationConfigMapReference{
			Name: configMapName,
		},
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy config with trustedCA")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Registering Keycloak as OIDC IdP (operator discovers it through the proxy)")
	idpCleans := test.AddKeycloakOIDCIdP(t, kubeConfig, setup, false)
	keycloakCleanups = append(keycloakCleanups, idpCleans...)

	g.By("Creating Keycloak test user and group")
	// Re-authenticate: the admin token from initial setup may have expired
	// during the operator reconciliation wait (~15 min).
	o.Expect(kcClient.AuthenticatePassword("admin-cli", "", "admin", "password")).To(o.Succeed())
	group := "ocp-test-ca-reload-group"
	o.Expect(kcClient.CreateGroup(group)).To(o.Succeed())

	username := "ca-reload-test-user"
	password := "ca-reload-test-password"
	o.Expect(kcClient.CreateUser(username, "", password, []string{group}, nil)).To(o.Succeed())

	logCutOff := time.Now()

	g.By("Verifying OIDC login works after setting proxy with trustedCA")
	assertOIDCLogin(t, kubeConfig, *clients, username, password, group)

	g.By("Verifying traffic went through the Squid proxy")
	issuerURL, err := url.Parse(kcClient.IssuerURL())
	o.Expect(err).NotTo(o.HaveOccurred())
	keycloakHost := issuerURL.Hostname()

	time.Sleep(2 * time.Minute)
	logs, err := test.GetSquidProxyLogsSince(clients.KubeClient, proxyNamespace, logCutOff)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(logs).To(o.ContainSubstring(keycloakHost))

	g.By("Verifying trustedCA ConfigMap is synced to openshift-authentication namespace")
	test.VerifyTrustedCAConfigMapSynced(t, clients.KubeClient, configMapName)

	g.By("Recording oauth-server pod names before CA rotation")
	oauthServerPodList, err := clients.KubeClient.CoreV1().Pods("openshift-authentication").List(ctx, metav1.ListOptions{LabelSelector: "app=oauth-openshift"})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(oauthServerPodList.Items).NotTo(o.BeEmpty())

	podNamesBefore := sets.New[string]()
	for _, pod := range oauthServerPodList.Items {
		podNamesBefore.Insert(pod.Name)
	}

	g.By("Rotating CA: generating new CA and server cert")
	newCA := test.NewCertificateAuthorityCertificate(t, nil)
	serviceDNS := fmt.Sprintf("squid-proxy.%s.svc.cluster.local", proxyNamespace)
	newServerCert := test.NewServerCertificate(t, newCA, serviceDNS)

	newCACertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCA.Certificate.Raw})
	newServerCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newServerCert.Certificate.Raw})
	newServerKeyDER, err := x509.MarshalPKCS8PrivateKey(newServerCert.PrivateKey)
	o.Expect(err).NotTo(o.HaveOccurred())
	newServerKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newServerKeyDER})

	g.By("Updating squid-tls Secret with rotated cert")
	tlsSecret, err := clients.KubeClient.CoreV1().Secrets(proxyNamespace).Get(ctx, "squid-tls", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	tlsSecret.Data["tls.crt"] = newServerCertPEM
	tlsSecret.Data["tls.key"] = newServerKeyPEM
	_, err = clients.KubeClient.CoreV1().Secrets(proxyNamespace).Update(ctx, tlsSecret, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Reconfiguring Squid to pick up new cert")
	squidPods, err := clients.KubeClient.CoreV1().Pods(proxyNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=squid-proxy",
	})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(squidPods.Items).NotTo(o.BeEmpty())

	reconfigureCmd := exec.Command("oc", "exec",
		"-n", proxyNamespace,
		squidPods.Items[0].Name,
		"-c", "squid",
		"--", "/usr/sbin/squid", "-k", "reconfigure",
	)
	output, err := reconfigureCmd.CombinedOutput()
	o.Expect(err).NotTo(o.HaveOccurred(), "squid reconfigure failed: %s", string(output))

	g.By("Updating trustedCA ConfigMap with new CA")
	cm, err := clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Get(ctx, configMapName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	cm.Data["ca-bundle.crt"] = string(newCACertPEM)
	_, err = clients.KubeClient.CoreV1().ConfigMaps("openshift-config").Update(ctx, cm, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	logCutOff = time.Now()

	g.By("Verifying OIDC login works after CA rotation")
	assertOIDCLogin(t, kubeConfig, *clients, username, password, group)

	g.By("Verifying traffic went through the Squid proxy")
	time.Sleep(2 * time.Minute)
	logs, err = test.GetSquidProxyLogsSince(clients.KubeClient, proxyNamespace, logCutOff)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(logs).To(o.ContainSubstring(keycloakHost))

	g.By("Verifying oauth-server pods were NOT redeployed after CA rotation")
	oauthServerPodListAfter, err := clients.KubeClient.CoreV1().Pods("openshift-authentication").List(ctx, metav1.ListOptions{LabelSelector: "app=oauth-openshift"})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(oauthServerPodListAfter.Items).NotTo(o.BeEmpty())

	podNamesAfter := sets.New[string]()
	for _, pod := range oauthServerPodListAfter.Items {
		podNamesAfter.Insert(pod.Name)
	}

	o.Expect(podNamesAfter.Equal(podNamesBefore)).To(o.BeTrue(), "oauth-server pods should not have been redeployed after CA file change")
}

func testNoProxy() {
	ctx := context.Background()
	t := g.GinkgoTB()
	kubeConfig := test.NewClientConfigForTest(t)
	clients := test.NewTestClients(t)

	test.CheckFeatureGateEnabledOrSkip(t, clients.ConfigClient, features.FeatureGateAuthenticationComponentProxy)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deploying Squid forward proxy")
	httpProxyURL, _, _, proxyNS, proxyCleanup := test.DeploySquidProxy(t, clients.KubeClient)
	g.DeferCleanup(proxyCleanup)

	g.By("Saving original proxy config")
	operatorAuth, proxyConfigCleanup := test.SaveAndRestoreProxyConfig(t, clients.OperatorClient, clients.ConfigClient)
	g.DeferCleanup(proxyConfigCleanup)

	g.By("Deploying Keycloak (without registering IdP yet)")
	setup := test.DeployKeycloak(t, kubeConfig)
	keycloakCleanups := setup.Cleanups
	kcClient := setup.Client
	g.DeferCleanup(test.IDPCleanupWrapper(func() {
		g.GinkgoWriter.Println("cleaning up: removing Keycloak and IdP")
		for _, cleanup := range keycloakCleanups {
			cleanup()
		}
	}))

	g.By("Enabling Direct Access Grants on Keycloak client for ROPC flow")
	enableDirectAccessGrants(kcClient, setup.ClientID)

	g.By("Adding OIDC IdP")
	idpCleans := test.AddKeycloakOIDCIdP(t, kubeConfig, setup, false)
	keycloakCleanups = append(keycloakCleanups, idpCleans...)

	issuerURL, err := url.Parse(kcClient.IssuerURL())
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Setting component-scoped proxy with noProxy")
	operatorAuth, err = clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: httpProxyURL,
		NoProxy:    []string{issuerURL.Hostname()},
	}

	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for operator to reconcile proxy config")
	err = test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating Keycloak test user and group")
	group := "ocp-test-no-proxy-group"
	o.Expect(kcClient.CreateGroup(group)).To(o.Succeed())

	username := "ca-no-proxy-test-user"
	password := "ca-no-proxy-test-password"
	o.Expect(kcClient.CreateUser(username, "", password, []string{group}, nil)).To(o.Succeed())

	g.By("Verifying OIDC login works after setting proxy with noProxy")
	assertOIDCLogin(t, kubeConfig, *clients, username, password, group)

	keycloakHost := issuerURL.Hostname()

	g.By("Waiting for squid logs to settle before checking for absence of proxy traffic")
	time.Sleep(2 * time.Minute)

	logs, err := test.GetSquidProxyLogs(clients.KubeClient, proxyNS)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(logs).NotTo(o.ContainSubstring(keycloakHost), "squid logs should not contain keycloak connect")
}

func enableDirectAccessGrants(kcClient *test.KeycloakClient, clientID string) {
	g.GinkgoHelper()
	kcClientObj, err := kcClient.GetClientByClientID(clientID)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(kcClient.UpdateClientDirectAccessGrantsEnabled(kcClientObj["id"].(string), true)).To(o.Succeed())
}

func assertOIDCLogin(t testing.TB, kubeConfig *rest.Config, routeClient test.TestClients, username, password, expectedGroup string) {
	g.GinkgoHelper()
	ctx := context.Background()

	route, err := routeClient.RouteClient.RouteV1().Routes("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "should be able to get the OAuth server route")
	oauthServerURL := fmt.Sprintf("https://%s", route.Spec.Host)

	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		tokenOpts := tokenrequest.NewRequestTokenOptions(rest.CopyConfig(kubeConfig), false)
		tokenOpts, err := tokenOpts.WithChallengeHandlers(
			challengehandlers.NewBasicChallengeHandler(oauthServerURL, "", nil, io.Discard, nil, username, password),
		)
		if err != nil {
			t.Logf("failed to create challenge handler: %v", err)
			return false, nil
		}

		token, err := tokenOpts.RequestToken()
		if err != nil {
			t.Logf("failed to request token: %v", err)
			return false, nil
		}
		if token == "" {
			t.Log("received empty token")
			return false, nil
		}

		tokenConfig := rest.AnonymousClientConfig(kubeConfig)
		tokenConfig.BearerToken = token
		tokenKubeClient, err := kubernetes.NewForConfig(tokenConfig)
		if err != nil {
			t.Logf("failed to create kube client with token: %v", err)
			return false, nil
		}

		ssr, err := tokenKubeClient.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil {
			t.Logf("failed to create SelfSubjectReview: %v", err)
			return false, nil
		}

		if ssr.Status.UserInfo.Username == "" {
			t.Log("SelfSubjectReview returned empty username")
			return false, nil
		}

		for _, g := range ssr.Status.UserInfo.Groups {
			if g == expectedGroup {
				return true, nil
			}
		}
		t.Logf("expected group %q not found in groups: %v", expectedGroup, ssr.Status.UserInfo.Groups)
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "OIDC login flow should succeed")
}
