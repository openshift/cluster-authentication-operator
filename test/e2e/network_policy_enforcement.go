package e2e

import (
	"context"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[NetworkPolicy][Disruptive][Serial] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should enforce auth NetworkPolicies", func() {
		testAuthNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should enforce oauth-apiserver NetworkPolicies", func() {
		testOAuthAPIServerNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should enforce authentication-operator NetworkPolicies", func() {
		testAuthenticationOperatorNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should block unauthorized namespace traffic", func() {
		testUnauthorizedNamespaceBlocking()
	})
})

func testGenericNetworkPolicyEnforcement() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := e2e.NewTestNamespaceBuilder("np-enforcement-").Create(t, kubeClient.CoreV1().Namespaces())
	defer func() {
		t.Logf("deleting test namespace %s", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{})
	}()

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	t.Logf("creating netexec server pod %s/%s", nsName, serverName)
	serverPod := NetexecPod(serverName, nsName, serverLabels, 8080)
	_, err = kubeClient.CoreV1().Pods(nsName).Create(ctx, serverPod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(WaitForPodReady(ctx, kubeClient, nsName, serverName)).NotTo(o.HaveOccurred())

	server, err := kubeClient.CoreV1().Pods(nsName).Get(ctx, serverName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(server.Status.PodIPs).NotTo(o.BeEmpty())
	serverIPs := PodIPs(server)
	t.Logf("server pod %s/%s ips=%v", nsName, serverName, serverIPs)

	g.By("Verifying allow-all when no policies select the pod")
	ExpectConnectivity(ctx, t, kubeClient, nsName, clientLabels, serverIPs, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	t.Logf("creating default-deny policy in %s", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, DefaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	t.Logf("creating allow-ingress policy in %s", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, AllowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	ExpectConnectivity(ctx, t, kubeClient, nsName, clientLabels, serverIPs, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	t.Logf("creating allow-egress policy in %s", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, AllowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	ExpectConnectivity(ctx, t, kubeClient, nsName, clientLabels, serverIPs, 8080, true)
}

func testAuthNetworkPolicyEnforcement() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	serverLabels := map[string]string{"app": "oauth-openshift"}

	g.By("Creating oauth server test pods for allow/deny checks")
	t.Logf("creating auth server pods in %s", namespace)
	allowedServerIPs, cleanupAllowed := CreateServerPod(ctx, t, kubeClient, namespace, "np-auth-allowed", serverLabels, 6443)
	defer cleanupAllowed()
	deniedServerIPs, cleanupDenied := CreateServerPod(ctx, t, kubeClient, namespace, "np-auth-denied", serverLabels, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 6443")
	ExpectConnectivity(ctx, t, kubeClient, namespace, clientLabels, allowedServerIPs, 6443, true)
	g.By("Verifying denied port 12345")
	ExpectConnectivity(ctx, t, kubeClient, namespace, clientLabels, deniedServerIPs, 12345, false)
}

func testOAuthAPIServerNetworkPolicyEnforcement() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	serverNamespace := "openshift-oauth-apiserver"
	clientNamespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	oauthClientLabels := map[string]string{"app": "openshift-oauth-apiserver"}
	_, err = kubeClient.NetworkingV1().NetworkPolicies(serverNamespace).Get(ctx, "oauth-apiserver-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating oauth-apiserver test pods for allow/deny checks")
	t.Logf("creating oauth-apiserver server pods in %s", serverNamespace)
	allowedServerIPs, cleanupAllowed := CreateServerPod(ctx, t, kubeClient, serverNamespace, "np-oauth-api-allowed", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupAllowed()
	deniedServerIPs, cleanupDenied := CreateServerPod(ctx, t, kubeClient, serverNamespace, "np-oauth-api-denied", map[string]string{"app": "openshift-oauth-apiserver"}, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 8443")
	ExpectConnectivity(ctx, t, kubeClient, clientNamespace, clientLabels, allowedServerIPs, 8443, true)

	g.By("Verifying denied port 12345")
	ExpectConnectivity(ctx, t, kubeClient, clientNamespace, clientLabels, deniedServerIPs, 12345, false)

	g.By("Verifying denied ports even from allowed namespace")
	for _, port := range []int32{80, 443, 6443, 9090} {
		ExpectConnectivity(ctx, t, kubeClient, clientNamespace, clientLabels, allowedServerIPs, port, false)
	}

	g.By("Verifying oauth-apiserver egress to DNS")
	dnsSvc, err := kubeClient.CoreV1().Services("openshift-dns").Get(ctx, "dns-default", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	dnsIPs := ServiceClusterIPs(dnsSvc)
	t.Logf("expecting allow from %s to DNS %v:53", serverNamespace, dnsIPs)
	ExpectConnectivity(ctx, t, kubeClient, serverNamespace, oauthClientLabels, dnsIPs, 53, true)

	g.By("Verifying oauth-apiserver egress to etcd (best-effort: etcd runs on hostNetwork and requires mTLS)")
	etcdSvc, err := kubeClient.CoreV1().Services("openshift-etcd").Get(ctx, "etcd", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	etcdIPs := ServiceClusterIPs(etcdSvc)
	t.Logf("etcd egress check (best-effort): %s -> %v:2379", serverNamespace, etcdIPs)
	t.Logf("note: etcd pods run on hostNetwork and require mTLS; agnhost connect may fail even if network policy allows egress")
	LogConnectivityBestEffort(ctx, t, kubeClient, serverNamespace, oauthClientLabels, etcdIPs, 2379, true)
}

func testAuthenticationOperatorNetworkPolicyEnforcement() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication-operator"
	serverLabels := map[string]string{"app": "authentication-operator"}
	clientLabels := map[string]string{"app": "authentication-operator"}
	policy, err := kubeClient.NetworkingV1().NetworkPolicies(namespace).Get(ctx, "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating authentication-operator test pods for policy checks")
	t.Logf("creating auth-operator server pod in %s", namespace)
	serverIPs, cleanupServer := CreateServerPod(ctx, t, kubeClient, namespace, "np-auth-op-server", serverLabels, 8443)
	defer cleanupServer()

	allowedFromSameNamespace := IngressAllowsFromNamespace(policy, namespace, clientLabels, 8443)
	g.By("Verifying within-namespace traffic matches policy")
	ExpectConnectivity(ctx, t, kubeClient, namespace, clientLabels, serverIPs, 8443, allowedFromSameNamespace)

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 12345, false)
}

func testCrossNamespaceIngressEnforcement() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIPs, cleanupAuthServer := CreateServerPod(ctx, t, kubeClient, "openshift-authentication", "np-auth-xns", map[string]string{"app": "oauth-openshift"}, 6443)
	defer cleanupAuthServer()
	oauthAPIServerIPs, cleanupOAuthAPIServer := CreateServerPod(ctx, t, kubeClient, "openshift-oauth-apiserver", "np-oauth-api-xns", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupOAuthAPIServer()
	authOperatorIPs, cleanupAuthOperator := CreateServerPod(ctx, t, kubeClient, "openshift-authentication-operator", "np-auth-op-xns", map[string]string{"app": "authentication-operator"}, 8443)
	defer cleanupAuthOperator()

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-server:6443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, authServerIPs, 6443, true)

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-apiserver:8443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: oauth-server -> oauth-apiserver:8443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-server:6443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authServerIPs, 6443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-apiserver:8443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> auth-operator:8443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authOperatorIPs, 8443, true)

	g.By("Testing allow-all ingress: arbitrary namespace -> oauth-server:6443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-ingress", map[string]string{"test": "arbitrary-client"}, authServerIPs, 6443, true)

	g.By("Testing denied cross-namespace: unauthorized namespace -> oauth-server on unauthorized port")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-ingress", map[string]string{"test": "arbitrary-client"}, authServerIPs, 8080, false)

	g.By("Testing allow-all includes other auth components: oauth-apiserver -> oauth-server:6443")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-oauth-apiserver", map[string]string{"app": "openshift-oauth-apiserver"}, authServerIPs, 6443, true)

	g.By("Testing egress blocking: wrong labels in openshift-authentication (default-deny blocks egress)")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication", map[string]string{"app": "wrong-app"}, oauthAPIServerIPs, 8443, false)
}

func testUnauthorizedNamespaceBlocking() {
	t := g.GinkgoTB()
	ctx := context.TODO()
	kubeConfig := e2e.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIPs, cleanupAuthServer := CreateServerPod(ctx, t, kubeClient, "openshift-authentication", "np-auth-unauth", map[string]string{"app": "oauth-openshift"}, 6443)
	defer cleanupAuthServer()
	oauthAPIServerIPs, cleanupOAuthAPIServer := CreateServerPod(ctx, t, kubeClient, "openshift-oauth-apiserver", "np-oauth-api-unauth", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupOAuthAPIServer()
	authOperatorIPs, cleanupAuthOperator := CreateServerPod(ctx, t, kubeClient, "openshift-authentication-operator", "np-auth-op-unauth", map[string]string{"app": "authentication-operator"}, 8443)
	defer cleanupAuthOperator()
	authOperatorPolicy, err := kubeClient.NetworkingV1().NetworkPolicies("openshift-authentication-operator").Get(ctx, "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Testing allow-all rules: oauth-server:6443 (oauth-proxy sidecars)")
	ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, 6443, true)

	g.By("Testing allow-all rules: oauth-apiserver:8443 (kube-apiserver webhook/aggregated APIs)")
	ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing strict blocking: unauthorized namespace -> auth-operator:8443")
	defaultAllowed := IngressAllowsFromNamespace(authOperatorPolicy, "default", map[string]string{"test": "unauthorized"}, 8443)
	ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "unauthorized"}, authOperatorIPs, 8443, defaultAllowed)

	g.By("Testing strict blocking: unauthorized pod in openshift-etcd -> auth-operator:8443")
	// Note: auth-operator ingress allows from openshift-etcd, but openshift-etcd has
	// its own default-deny + allow-all-egress policy that only permits egress for pods
	// with app in (guard, installer, pruner, cluster-backup-cronjob).
	// A pod with {"test": "unauthorized"} labels is blocked by etcd's egress policy.
	ExpectConnectivity(ctx, t, kubeClient, "openshift-etcd", map[string]string{"test": "unauthorized"}, authOperatorIPs, 8443, false)

	g.By("Testing port-based blocking: unauthorized port even from any namespace")
	ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIPs, 9999, false)

	g.By("Testing port-based blocking: unauthorized port on oauth-server")
	ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, 9999, false)

	g.By("Testing allow-all ingress: wrong labels from allowed namespace")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-monitoring", map[string]string{"app": "wrong-label"}, authOperatorIPs, 8443, true)

	g.By("Testing egress blocking: wrong labels in openshift-authentication (default-deny blocks egress)")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication", map[string]string{"app": "wrong-label"}, oauthAPIServerIPs, 8443, false)

	g.By("Testing multiple unauthorized ports on oauth-server")
	for _, port := range []int32{80, 443, 8080, 8443, 22, 3306} {
		ExpectConnectivity(ctx, t, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, port, false)
	}

	g.By("Testing allow-all ingress: oauth-server can reach auth-operator")
	ExpectConnectivity(ctx, t, kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, authOperatorIPs, 8443, true)
}
