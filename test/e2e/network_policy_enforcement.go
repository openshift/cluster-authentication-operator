package e2e

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	e2e "github.com/openshift/cluster-authentication-operator/test/library"
)

const (
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.45"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[NetworkPolicy][Disruptive] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive] should enforce auth NetworkPolicies", func() {
		testAuthNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive] should enforce oauth-apiserver NetworkPolicies", func() {
		testOAuthAPIServerNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive] should enforce authentication-operator NetworkPolicies", func() {
		testAuthenticationOperatorNetworkPolicyEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[NetworkPolicy][Disruptive] should block unauthorized namespace traffic", func() {
		testUnauthorizedNamespaceBlocking()
	})
})

func testGenericNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := e2e.NewTestNamespaceBuilder("np-enforcement-").Create(g.GinkgoTB(), kubeClient.CoreV1().Namespaces())
	g.DeferCleanup(func() {
		g.GinkgoWriter.Printf("deleting test namespace %s\n", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{})
	})

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	g.GinkgoWriter.Printf("creating netexec server pod %s/%s\n", nsName, serverName)
	serverPod := netexecPod(serverName, nsName, serverLabels, 8080)
	_, err = kubeClient.CoreV1().Pods(nsName).Create(ctx, serverPod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(ctx, kubeClient, nsName, serverName)).NotTo(o.HaveOccurred())

	server, err := kubeClient.CoreV1().Pods(nsName).Get(ctx, serverName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(server.Status.PodIPs).NotTo(o.BeEmpty())
	serverIPs := podIPs(server)
	g.GinkgoWriter.Printf("server pod %s/%s ips=%v\n", nsName, serverName, serverIPs)

	g.By("Verifying allow-all when no policies select the pod")
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	g.GinkgoWriter.Printf("creating default-deny policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	g.GinkgoWriter.Printf("creating allow-ingress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	g.GinkgoWriter.Printf("creating allow-egress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, true)
}

func testAuthNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	serverLabels := map[string]string{"app": "oauth-openshift"}

	g.By("Creating oauth server test pods for allow/deny checks")
	g.GinkgoWriter.Printf("creating auth server pods in %s\n", namespace)
	allowedServerIPs, cleanupAllowed := createServerPod(ctx, kubeClient, namespace, fmt.Sprintf("np-auth-allowed-%s", rand.String(5)), serverLabels, 6443)
	g.DeferCleanup(cleanupAllowed)
	deniedServerIPs, cleanupDenied := createServerPod(ctx, kubeClient, namespace, fmt.Sprintf("np-auth-denied-%s", rand.String(5)), serverLabels, 12345)
	g.DeferCleanup(cleanupDenied)

	g.By("Verifying allowed port 6443")
	expectConnectivity(ctx, kubeClient, namespace, clientLabels, allowedServerIPs, 6443, true)
	g.By("Verifying denied port 12345")
	expectConnectivity(ctx, kubeClient, namespace, clientLabels, deniedServerIPs, 12345, false)
}

func testOAuthAPIServerNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	serverNamespace := "openshift-oauth-apiserver"
	clientNamespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	oauthClientLabels := map[string]string{"app": "openshift-oauth-apiserver"}
	_, err = kubeClient.NetworkingV1().NetworkPolicies(serverNamespace).Get(ctx, "oauth-apiserver-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating oauth-apiserver test pods for allow/deny checks")
	g.GinkgoWriter.Printf("creating oauth-apiserver server pods in %s\n", serverNamespace)
	allowedServerIPs, cleanupAllowed := createServerPod(ctx, kubeClient, serverNamespace, fmt.Sprintf("np-oauth-api-allowed-%s", rand.String(5)), map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	g.DeferCleanup(cleanupAllowed)
	deniedServerIPs, cleanupDenied := createServerPod(ctx, kubeClient, serverNamespace, fmt.Sprintf("np-oauth-api-denied-%s", rand.String(5)), map[string]string{"app": "openshift-oauth-apiserver"}, 12345)
	g.DeferCleanup(cleanupDenied)

	g.By("Verifying allowed port 8443")
	expectConnectivity(ctx, kubeClient, clientNamespace, clientLabels, allowedServerIPs, 8443, true)

	g.By("Verifying denied port 12345")
	expectConnectivity(ctx, kubeClient, clientNamespace, clientLabels, deniedServerIPs, 12345, false)

	g.By("Verifying denied ports even from allowed namespace")
	for _, port := range []int32{80, 443, 6443, 9090} {
		expectConnectivity(ctx, kubeClient, clientNamespace, clientLabels, allowedServerIPs, port, false)
	}

	g.By("Verifying oauth-apiserver egress to DNS")
	dnsSvc, err := kubeClient.CoreV1().Services("openshift-dns").Get(ctx, "dns-default", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	dnsIPs := serviceClusterIPs(dnsSvc)
	g.GinkgoWriter.Printf("expecting allow from %s to DNS %v:53\n", serverNamespace, dnsIPs)
	expectConnectivity(ctx, kubeClient, serverNamespace, oauthClientLabels, dnsIPs, 53, true)

	g.By("Verifying oauth-apiserver egress to etcd (best-effort: etcd runs on hostNetwork and requires mTLS)")
	etcdSvc, err := kubeClient.CoreV1().Services("openshift-etcd").Get(ctx, "etcd", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	etcdIPs := serviceClusterIPs(etcdSvc)
	g.GinkgoWriter.Printf("etcd egress check (best-effort): %s -> %v:2379\n", serverNamespace, etcdIPs)
	g.GinkgoWriter.Printf("note: etcd pods run on hostNetwork and require mTLS; agnhost connect may fail even if network policy allows egress\n")
	logConnectivityBestEffort(ctx, kubeClient, serverNamespace, oauthClientLabels, etcdIPs, 2379, true)
}

func testAuthenticationOperatorNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication-operator"
	serverLabels := map[string]string{"app": "authentication-operator"}
	clientLabels := map[string]string{"app": "authentication-operator"}
	policy, err := kubeClient.NetworkingV1().NetworkPolicies(namespace).Get(ctx, "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating authentication-operator test pods for policy checks")
	g.GinkgoWriter.Printf("creating auth-operator server pod in %s\n", namespace)
	serverIPs, cleanupServer := createServerPod(ctx, kubeClient, namespace, fmt.Sprintf("np-auth-op-server-%s", rand.String(5)), serverLabels, 8443)
	g.DeferCleanup(cleanupServer)

	allowedFromSameNamespace := ingressAllowsFromNamespace(policy, namespace, clientLabels, 8443)
	g.By("Verifying within-namespace traffic matches policy")
	expectConnectivity(ctx, kubeClient, namespace, clientLabels, serverIPs, 8443, allowedFromSameNamespace)

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 12345, false)
}

func testCrossNamespaceIngressEnforcement() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIPs, cleanupAuthServer := createServerPod(ctx, kubeClient, "openshift-authentication", fmt.Sprintf("np-auth-xns-%s", rand.String(5)), map[string]string{"app": "oauth-openshift"}, 6443)
	g.DeferCleanup(cleanupAuthServer)
	oauthAPIServerIPs, cleanupOAuthAPIServer := createServerPod(ctx, kubeClient, "openshift-oauth-apiserver", fmt.Sprintf("np-oauth-api-xns-%s", rand.String(5)), map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	g.DeferCleanup(cleanupOAuthAPIServer)
	authOperatorIPs, cleanupAuthOperator := createServerPod(ctx, kubeClient, "openshift-authentication-operator", fmt.Sprintf("np-auth-op-xns-%s", rand.String(5)), map[string]string{"app": "authentication-operator"}, 8443)
	g.DeferCleanup(cleanupAuthOperator)

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-server:6443")
	expectConnectivity(ctx, kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, authServerIPs, 6443, true)

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-apiserver:8443")
	expectConnectivity(ctx, kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: oauth-server -> oauth-apiserver:8443")
	expectConnectivity(ctx, kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-server:6443")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authServerIPs, 6443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-apiserver:8443")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> auth-operator:8443")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authOperatorIPs, 8443, true)

	g.By("Testing allow-all ingress: arbitrary namespace -> oauth-server:6443")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, authServerIPs, 6443, true)

	g.By("Testing denied cross-namespace: unauthorized namespace -> oauth-server on unauthorized port")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, authServerIPs, 8080, false)

	g.By("Testing allow-all includes other auth components: oauth-apiserver -> oauth-server:6443")
	expectConnectivity(ctx, kubeClient, "openshift-oauth-apiserver", map[string]string{"app": "openshift-oauth-apiserver"}, authServerIPs, 6443, true)

	g.By("Testing egress blocking: wrong labels in openshift-authentication (default-deny blocks egress)")
	expectConnectivity(ctx, kubeClient, "openshift-authentication", map[string]string{"app": "wrong-app"}, oauthAPIServerIPs, 8443, false)
}

func testUnauthorizedNamespaceBlocking() {
	ctx := context.Background()
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIPs, cleanupAuthServer := createServerPod(ctx, kubeClient, "openshift-authentication", fmt.Sprintf("np-auth-unauth-%s", rand.String(5)), map[string]string{"app": "oauth-openshift"}, 6443)
	g.DeferCleanup(cleanupAuthServer)
	oauthAPIServerIPs, cleanupOAuthAPIServer := createServerPod(ctx, kubeClient, "openshift-oauth-apiserver", fmt.Sprintf("np-oauth-api-unauth-%s", rand.String(5)), map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	g.DeferCleanup(cleanupOAuthAPIServer)
	authOperatorIPs, cleanupAuthOperator := createServerPod(ctx, kubeClient, "openshift-authentication-operator", fmt.Sprintf("np-auth-op-unauth-%s", rand.String(5)), map[string]string{"app": "authentication-operator"}, 8443)
	g.DeferCleanup(cleanupAuthOperator)
	authOperatorPolicy, err := kubeClient.NetworkingV1().NetworkPolicies("openshift-authentication-operator").Get(ctx, "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Testing allow-all rules: oauth-server:6443 (oauth-proxy sidecars)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, 6443, true)

	g.By("Testing allow-all rules: oauth-apiserver:8443 (kube-apiserver webhook/aggregated APIs)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIPs, 8443, true)

	g.By("Testing strict blocking: unauthorized namespace -> auth-operator:8443")
	defaultAllowed := ingressAllowsFromNamespace(authOperatorPolicy, "default", map[string]string{"test": "unauthorized"}, 8443)
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "unauthorized"}, authOperatorIPs, 8443, defaultAllowed)

	g.By("Testing strict blocking: unauthorized pod in openshift-etcd -> auth-operator:8443")
	// auth-operator ingress allows from openshift-etcd, but openshift-etcd has
	// its own default-deny + allow-all-egress policy that only permits egress for pods
	// with app in (guard, installer, pruner, cluster-backup-cronjob).
	// A pod with {"test": "unauthorized"} labels is blocked by etcd's egress policy.
	expectConnectivity(ctx, kubeClient, "openshift-etcd", map[string]string{"test": "unauthorized"}, authOperatorIPs, 8443, false)

	g.By("Testing port-based blocking: unauthorized port even from any namespace")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIPs, 9999, false)

	g.By("Testing port-based blocking: unauthorized port on oauth-server")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, 9999, false)

	g.By("Testing allow-all ingress: wrong labels from allowed namespace")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app": "wrong-label"}, authOperatorIPs, 8443, true)

	g.By("Testing egress blocking: wrong labels in openshift-authentication (default-deny blocks egress)")
	expectConnectivity(ctx, kubeClient, "openshift-authentication", map[string]string{"app": "wrong-label"}, oauthAPIServerIPs, 8443, false)

	g.By("Testing multiple unauthorized ports on oauth-server")
	for _, port := range []int32{80, 443, 8080, 8443, 22, 3306} {
		expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIPs, port, false)
	}

	g.By("Testing allow-all ingress: oauth-server can reach auth-operator")
	expectConnectivity(ctx, kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, authOperatorIPs, 8443, true)
}

func netexecPod(name, namespace string, labels map[string]string, port int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"openshift.io/required-scc": "nonroot-v2",
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolptr(true),
				RunAsUser:      int64ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "netexec",
					Image: agnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolptr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolptr(true),
						RunAsUser:                int64ptr(1001),
					},
					Command: []string{"/agnhost"},
					Args:    []string{"netexec", fmt.Sprintf("--http-port=%d", port)},
					Ports: []corev1.ContainerPort{
						{ContainerPort: port},
					},
				},
			},
		},
	}
}

func createServerPod(ctx context.Context, kubeClient kubernetes.Interface, namespace, name string, labels map[string]string, port int32) ([]string, func()) {
	g.GinkgoHelper()

	g.GinkgoWriter.Printf("creating server pod %s/%s port=%d labels=%v\n", namespace, name, port, labels)
	pod := netexecPod(name, namespace, labels, port)
	_, err := kubeClient.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(ctx, kubeClient, namespace, name)).NotTo(o.HaveOccurred())

	created, err := kubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(created.Status.PodIPs).NotTo(o.BeEmpty())

	ips := podIPs(created)
	g.GinkgoWriter.Printf("server pod %s/%s ips=%v\n", namespace, name, ips)

	return ips, func() {
		g.GinkgoWriter.Printf("deleting server pod %s/%s\n", namespace, name)
		_ = kubeClient.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	}
}

func podIPs(pod *corev1.Pod) []string {
	var ips []string
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" {
			ips = append(ips, podIP.IP)
		}
	}
	if len(ips) == 0 && pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}
	return ips
}

func isIPv6(ip string) bool {
	return net.ParseIP(ip) != nil && strings.Contains(ip, ":")
}

func formatIPPort(ip string, port int32) string {
	if isIPv6(ip) {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func serviceClusterIPs(svc *corev1.Service) []string {
	if len(svc.Spec.ClusterIPs) > 0 {
		return svc.Spec.ClusterIPs
	}
	if svc.Spec.ClusterIP != "" {
		return []string{svc.Spec.ClusterIP}
	}
	return nil
}

func defaultDenyPolicy(name, namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func allowIngressPolicy(name, namespace string, podLabels, fromLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: fromLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
}

func allowEgressPolicy(name, namespace string, podLabels, toLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: toLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
}

func expectConnectivityForIP(ctx context.Context, kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	podName, cleanup, err := createConnectivityClientPod(ctx, kubeClient, namespace, clientLabels, serverIP, port)
	o.Expect(err).NotTo(o.HaveOccurred())
	g.DeferCleanup(cleanup)

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		succeeded, err := readConnectivityResult(ctx, kubeClient, namespace, podName)
		if err != nil {
			g.GinkgoWriter.Printf("waiting for connectivity result: %v\n", err)
			return false, nil
		}
		return succeeded == shouldSucceed, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("connectivity %s/%s expected=%t\n", namespace, formatIPPort(serverIP, port), shouldSucceed)
}

func expectConnectivity(ctx context.Context, kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIPs []string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	for _, ip := range serverIPs {
		family := "IPv4"
		if isIPv6(ip) {
			family = "IPv6"
		}
		g.GinkgoWriter.Printf("checking %s connectivity %s -> %s expected=%t\n", family, namespace, formatIPPort(ip, port), shouldSucceed)
		expectConnectivityForIP(ctx, kubeClient, namespace, clientLabels, ip, port, shouldSucceed)
	}
}

func logConnectivityBestEffortForIP(ctx context.Context, kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	podName, cleanup, err := createConnectivityClientPod(ctx, kubeClient, namespace, clientLabels, serverIP, port)
	if err != nil {
		g.GinkgoWriter.Printf("failed to create client pod for best-effort check: %v\n", err)
		return
	}
	g.DeferCleanup(cleanup)

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		succeeded, err := readConnectivityResult(ctx, kubeClient, namespace, podName)
		if err != nil {
			return false, nil
		}
		return succeeded == shouldSucceed, nil
	})
	if err != nil {
		g.GinkgoWriter.Printf("connectivity %s/%s expected=%t (best-effort) failed: %v\n", namespace, formatIPPort(serverIP, port), shouldSucceed, err)
		return
	}
	g.GinkgoWriter.Printf("connectivity %s/%s expected=%t (best-effort)\n", namespace, formatIPPort(serverIP, port), shouldSucceed)
}

func logConnectivityBestEffort(ctx context.Context, kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIPs []string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	for _, ip := range serverIPs {
		family := "IPv4"
		if isIPv6(ip) {
			family = "IPv6"
		}
		g.GinkgoWriter.Printf("checking %s connectivity (best-effort) %s -> %s expected=%t\n", family, namespace, formatIPPort(ip, port), shouldSucceed)
		logConnectivityBestEffortForIP(ctx, kubeClient, namespace, clientLabels, ip, port, shouldSucceed)
	}
}

// createConnectivityClientPod creates a long-running pod that continuously probes
// TCP connectivity and writes results to stdout. Callers read the pod's logs
// to determine the latest result, avoiding per-poll pod create/delete overhead.
func createConnectivityClientPod(ctx context.Context, kubeClient kubernetes.Interface, namespace string, labels map[string]string, serverIP string, port int32) (string, func(), error) {
	name := fmt.Sprintf("np-client-%s", rand.String(5))
	target := formatIPPort(serverIP, port)

	g.GinkgoWriter.Printf("creating client pod %s/%s to probe %s\n", namespace, name, target)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"openshift.io/required-scc": "nonroot-v2",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolptr(true),
				RunAsUser:      int64ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "connect",
					Image: agnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolptr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolptr(true),
						RunAsUser:                int64ptr(1001),
					},
					Command: []string{"/bin/sh", "-c"},
					Args: []string{
						fmt.Sprintf("while true; do if /agnhost connect --protocol=tcp --timeout=5s %s 2>/dev/null; then echo CONN_OK; else echo CONN_FAIL; fi; sleep 3; done", target),
					},
				},
			},
		},
	}

	_, err := kubeClient.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return "", nil, err
	}

	if err := waitForPodReady(ctx, kubeClient, namespace, name); err != nil {
		_ = kubeClient.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		return "", nil, fmt.Errorf("client pod %s/%s never became ready: %w", namespace, name, err)
	}

	cleanup := func() {
		g.GinkgoWriter.Printf("deleting client pod %s/%s\n", namespace, name)
		_ = kubeClient.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	}

	return name, cleanup, nil
}

func readConnectivityResult(ctx context.Context, kubeClient kubernetes.Interface, namespace, podName string) (bool, error) {
	tailLines := int64(1)
	raw, err := kubeClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		TailLines: &tailLines,
	}).DoRaw(ctx)
	if err != nil {
		return false, err
	}

	line := strings.TrimSpace(string(raw))
	if line == "" {
		return false, fmt.Errorf("no connectivity result yet from pod %s/%s", namespace, podName)
	}

	g.GinkgoWriter.Printf("client pod %s/%s result=%s\n", namespace, podName, line)
	return line == "CONN_OK", nil
}

func ingressAllowsFromNamespace(policy *networkingv1.NetworkPolicy, namespace string, labels map[string]string, port int32) bool {
	for _, rule := range policy.Spec.Ingress {
		if !ruleAllowsPort(rule.Ports, port) {
			continue
		}
		if len(rule.From) == 0 {
			return true
		}
		for _, peer := range rule.From {
			if peer.NamespaceSelector != nil {
				if nsMatch(peer.NamespaceSelector, namespace) && podMatch(peer.PodSelector, labels) {
					return true
				}
				continue
			}
			if podMatch(peer.PodSelector, labels) {
				return true
			}
		}
	}
	return false
}

func nsMatch(selector *metav1.LabelSelector, namespace string) bool {
	if selector == nil {
		return true
	}
	if selector.MatchLabels != nil {
		if selector.MatchLabels["kubernetes.io/metadata.name"] == namespace {
			return true
		}
	}
	for _, expr := range selector.MatchExpressions {
		if expr.Key != "kubernetes.io/metadata.name" {
			continue
		}
		if expr.Operator != metav1.LabelSelectorOpIn {
			continue
		}
		if slices.Contains(expr.Values, namespace) {
			return true
		}
	}
	return false
}

func podMatch(selector *metav1.LabelSelector, labels map[string]string) bool {
	if selector == nil {
		return true
	}
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func ruleAllowsPort(ports []networkingv1.NetworkPolicyPort, port int32) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Port == nil {
			return true
		}
		if p.Port.Type == intstr.Int && p.Port.IntVal == port {
			return true
		}
	}
	return false
}

func waitForPodReady(ctx context.Context, kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

func protocolPtr(protocol corev1.Protocol) *corev1.Protocol {
	return &protocol
}

func boolptr(value bool) *bool {
	return &value
}

func int64ptr(value int64) *int64 {
	return &value
}
