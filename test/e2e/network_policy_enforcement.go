package e2e

import (
	"context"
	"fmt"
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
	g.It("[Operator][NetworkPolicy] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce auth NetworkPolicies", func() {
		testAuthNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce oauth-apiserver NetworkPolicies", func() {
		testOAuthAPIServerNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce authentication-operator NetworkPolicies", func() {
		testAuthenticationOperatorNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should block unauthorized namespace traffic", func() {
		testUnauthorizedNamespaceBlocking()
	})
})

func testGenericNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := e2e.NewTestNamespaceBuilder("np-enforcement-").Create(g.GinkgoTB(), kubeClient.CoreV1().Namespaces())
	defer func() {
		g.GinkgoWriter.Printf("deleting test namespace %s\n", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(context.TODO(), nsName, metav1.DeleteOptions{})
	}()

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	g.GinkgoWriter.Printf("creating netexec server pod %s/%s\n", nsName, serverName)
	serverPod := netexecPod(serverName, nsName, serverLabels, 8080)
	_, err = kubeClient.CoreV1().Pods(nsName).Create(context.TODO(), serverPod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(kubeClient, nsName, serverName)).NotTo(o.HaveOccurred())

	server, err := kubeClient.CoreV1().Pods(nsName).Get(context.TODO(), serverName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(server.Status.PodIP).NotTo(o.BeEmpty())
	g.GinkgoWriter.Printf("server pod %s/%s ip=%s\n", nsName, serverName, server.Status.PodIP)

	g.By("Verifying allow-all when no policies select the pod")
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	g.GinkgoWriter.Printf("creating default-deny policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	g.GinkgoWriter.Printf("creating allow-ingress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d (egress still blocked)\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	g.GinkgoWriter.Printf("creating allow-egress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, true)
}

func testAuthNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	serverLabels := map[string]string{"app": "oauth-openshift"}

	g.By("Creating oauth server test pods for allow/deny checks")
	g.GinkgoWriter.Printf("creating auth server pods in %s\n", namespace)
	allowedServerIP, cleanupAllowed := createServerPod(kubeClient, namespace, "np-auth-allowed", serverLabels, 6443)
	defer cleanupAllowed()
	deniedServerIP, cleanupDenied := createServerPod(kubeClient, namespace, "np-auth-denied", serverLabels, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 6443")
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", namespace, allowedServerIP, 6443)
	expectConnectivity(kubeClient, namespace, clientLabels, allowedServerIP, 6443, true)
	g.By("Verifying denied port 12345")
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d\n", namespace, deniedServerIP, 12345)
	expectConnectivity(kubeClient, namespace, clientLabels, deniedServerIP, 12345, false)
}

func testOAuthAPIServerNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	serverNamespace := "openshift-oauth-apiserver"
	clientNamespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}
	oauthClientLabels := map[string]string{"app": "openshift-oauth-apiserver"}
	oauthPolicy, err := kubeClient.NetworkingV1().NetworkPolicies(serverNamespace).Get(context.TODO(), "oauth-apiserver-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating oauth-apiserver test pods for allow/deny checks")
	g.GinkgoWriter.Printf("creating oauth-apiserver server pods in %s\n", serverNamespace)
	allowedServerIP, cleanupAllowed := createServerPod(kubeClient, serverNamespace, "np-oauth-api-allowed", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupAllowed()
	deniedServerIP, cleanupDenied := createServerPod(kubeClient, serverNamespace, "np-oauth-api-denied", map[string]string{"app": "openshift-oauth-apiserver"}, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 8443")
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", clientNamespace, allowedServerIP, 8443)
	expectConnectivity(kubeClient, clientNamespace, clientLabels, allowedServerIP, 8443, true)

	g.By("Verifying denied port 12345")
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d\n", clientNamespace, deniedServerIP, 12345)
	expectConnectivity(kubeClient, clientNamespace, clientLabels, deniedServerIP, 12345, false)

	g.By("Verifying denied ports even from allowed namespace")
	for _, port := range []int32{80, 443, 6443, 9090} {
		g.GinkgoWriter.Printf("expecting deny from %s to %s:%d\n", clientNamespace, allowedServerIP, port)
		expectConnectivity(kubeClient, clientNamespace, clientLabels, allowedServerIP, port, false)
	}

	g.By("Verifying oauth-apiserver egress to DNS")
	dnsSvc, err := kubeClient.CoreV1().Services("openshift-dns").Get(context.TODO(), "dns-default", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	dnsIP := dnsSvc.Spec.ClusterIP
	g.GinkgoWriter.Printf("expecting allow from %s to DNS %s:53\n", serverNamespace, dnsIP)
	expectConnectivity(kubeClient, serverNamespace, oauthClientLabels, dnsIP, 53, true)

	g.By("Verifying oauth-apiserver egress to etcd")
	etcdSvc, err := kubeClient.CoreV1().Services("openshift-etcd").Get(context.TODO(), "etcd", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	etcdIP := etcdSvc.Spec.ClusterIP
	etcdAllowed := egressAllowsNamespace(oauthPolicy, "openshift-etcd", 2379)
	g.GinkgoWriter.Printf("expecting %s from %s to etcd %s:2379\n", boolToAllowDeny(etcdAllowed), serverNamespace, etcdIP)
	logConnectivityBestEffort(kubeClient, serverNamespace, oauthClientLabels, etcdIP, 2379)
}

func testAuthenticationOperatorNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-authentication-operator"
	serverLabels := map[string]string{"app": "authentication-operator"}
	clientLabels := map[string]string{"app": "authentication-operator"}
	policy, err := kubeClient.NetworkingV1().NetworkPolicies(namespace).Get(context.TODO(), "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating authentication-operator test pods for policy checks")
	g.GinkgoWriter.Printf("creating auth-operator server pod in %s\n", namespace)
	serverIP, cleanupServer := createServerPod(kubeClient, namespace, "np-auth-op-server", serverLabels, 8443)
	defer cleanupServer()

	allowedFromSameNamespace := ingressAllowsFromNamespace(policy, namespace, clientLabels, 8443)
	g.By("Verifying within-namespace traffic matches policy")
	g.GinkgoWriter.Printf("expecting %s from same namespace to %s:%d\n", boolToAllowDeny(allowedFromSameNamespace), serverIP, 8443)
	expectConnectivity(kubeClient, namespace, clientLabels, serverIP, 8443, allowedFromSameNamespace)

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:%d\n", serverIP, 8443)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIP, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	g.GinkgoWriter.Printf("expecting deny from openshift-monitoring to %s:%d (unauthorized port)\n", serverIP, 12345)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIP, 12345, false)
}

func testCrossNamespaceIngressEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIP, cleanupAuthServer := createServerPod(kubeClient, "openshift-authentication", "np-auth-xns", map[string]string{"app": "oauth-openshift"}, 6443)
	defer cleanupAuthServer()
	oauthAPIServerIP, cleanupOAuthAPIServer := createServerPod(kubeClient, "openshift-oauth-apiserver", "np-oauth-api-xns", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupOAuthAPIServer()
	authOperatorIP, cleanupAuthOperator := createServerPod(kubeClient, "openshift-authentication-operator", "np-auth-op-xns", map[string]string{"app": "authentication-operator"}, 8443)
	defer cleanupAuthOperator()

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-server:6443")
	g.GinkgoWriter.Printf("expecting allow from openshift-authentication-operator to %s:6443\n", authServerIP)
	expectConnectivity(kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, authServerIP, 6443, true)

	g.By("Testing cross-namespace ingress: auth-operator -> oauth-apiserver:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-authentication-operator to %s:8443\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "openshift-authentication-operator", map[string]string{"app": "authentication-operator"}, oauthAPIServerIP, 8443, true)

	g.By("Testing cross-namespace ingress: oauth-server -> oauth-apiserver:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-authentication to %s:8443\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, oauthAPIServerIP, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-server:6443")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:6443\n", authServerIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authServerIP, 6443, true)

	g.By("Testing cross-namespace ingress: monitoring -> oauth-apiserver:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:8443\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, oauthAPIServerIP, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> auth-operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:8443\n", authOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, authOperatorIP, 8443, true)

	g.By("Testing allow-all ingress: arbitrary namespace -> oauth-server:6443")
	g.GinkgoWriter.Printf("expecting allow from any namespace to %s:6443 (oauth-proxy sidecars)\n", authServerIP)
	expectConnectivity(kubeClient, "openshift-ingress", map[string]string{"test": "arbitrary-client"}, authServerIP, 6443, true)

	g.By("Testing denied cross-namespace: unauthorized namespace -> oauth-server on unauthorized port")
	g.GinkgoWriter.Printf("expecting deny from openshift-ingress to %s:8080\n", authServerIP)
	expectConnectivity(kubeClient, "openshift-ingress", map[string]string{"test": "arbitrary-client"}, authServerIP, 8080, false)

	g.By("Testing allow-all includes other auth components: oauth-apiserver -> oauth-server:6443")
	g.GinkgoWriter.Printf("expecting allow from openshift-oauth-apiserver to %s:6443 (via allow-all rule)\n", authServerIP)
	expectConnectivity(kubeClient, "openshift-oauth-apiserver", map[string]string{"app": "openshift-oauth-apiserver"}, authServerIP, 6443, true)

	g.By("Testing denied cross-namespace: wrong labels from allowed namespace")
	g.GinkgoWriter.Printf("expecting deny from openshift-authentication (wrong labels) to %s:8443\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "openshift-authentication", map[string]string{"app": "wrong-app"}, oauthAPIServerIP, 8443, false)
}

func testUnauthorizedNamespaceBlocking() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in auth namespaces")
	authServerIP, cleanupAuthServer := createServerPod(kubeClient, "openshift-authentication", "np-auth-unauth", map[string]string{"app": "oauth-openshift"}, 6443)
	defer cleanupAuthServer()
	oauthAPIServerIP, cleanupOAuthAPIServer := createServerPod(kubeClient, "openshift-oauth-apiserver", "np-oauth-api-unauth", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupOAuthAPIServer()
	authOperatorIP, cleanupAuthOperator := createServerPod(kubeClient, "openshift-authentication-operator", "np-auth-op-unauth", map[string]string{"app": "authentication-operator"}, 8443)
	defer cleanupAuthOperator()
	authOperatorPolicy, err := kubeClient.NetworkingV1().NetworkPolicies("openshift-authentication-operator").Get(context.TODO(), "authentication-operator-networkpolicy", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Testing allow-all rules: oauth-server:6443 (oauth-proxy sidecars)")
	g.GinkgoWriter.Printf("expecting allow from default namespace to %s:6443 (oauth-proxy sidecar access)\n", authServerIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIP, 6443, true)

	g.By("Testing allow-all rules: oauth-apiserver:8443 (kube-apiserver webhook/aggregated APIs)")
	g.GinkgoWriter.Printf("expecting allow from default namespace to %s:8443 (kube-apiserver access)\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIP, 8443, true)

	g.By("Testing strict blocking: unauthorized namespace -> auth-operator:8443")
	defaultAllowed := ingressAllowsFromNamespace(authOperatorPolicy, "default", map[string]string{"test": "unauthorized"}, 8443)
	g.GinkgoWriter.Printf("expecting %s from default to %s:8443\n", boolToAllowDeny(defaultAllowed), authOperatorIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "unauthorized"}, authOperatorIP, 8443, defaultAllowed)

	g.By("Testing strict blocking: unauthorized namespace -> auth-operator:8443")
	etcdAllowed := ingressAllowsFromNamespace(authOperatorPolicy, "openshift-etcd", map[string]string{"test": "unauthorized"}, 8443)
	g.GinkgoWriter.Printf("expecting %s from openshift-etcd to %s:8443\n", boolToAllowDeny(etcdAllowed), authOperatorIP)
	expectConnectivity(kubeClient, "openshift-etcd", map[string]string{"test": "unauthorized"}, authOperatorIP, 8443, etcdAllowed)

	g.By("Testing port-based blocking: unauthorized port even from any namespace")
	g.GinkgoWriter.Printf("expecting deny from default to %s:9999 (unauthorized port)\n", oauthAPIServerIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, oauthAPIServerIP, 9999, false)

	g.By("Testing port-based blocking: unauthorized port on oauth-server")
	g.GinkgoWriter.Printf("expecting deny from default to %s:9999 (unauthorized port)\n", authServerIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIP, 9999, false)

	g.By("Testing label-based traffic from monitoring (best-effort)")
	monitoringLabels := map[string]string{"app": "wrong-label"}
	g.GinkgoWriter.Printf("checking connectivity from openshift-monitoring with wrong labels to %s:8443\n", authOperatorIP)
	logConnectivityBestEffort(kubeClient, "openshift-monitoring", monitoringLabels, authOperatorIP, 8443)

	g.By("Testing label-based traffic from openshift-authentication (best-effort)")
	authWrongLabels := map[string]string{"app": "wrong-label"}
	g.GinkgoWriter.Printf("checking connectivity from openshift-authentication with wrong labels to %s:8443\n", oauthAPIServerIP)
	logConnectivityBestEffort(kubeClient, "openshift-authentication", authWrongLabels, oauthAPIServerIP, 8443)

	g.By("Testing multiple unauthorized ports on oauth-server")
	for _, port := range []int32{80, 443, 8080, 8443, 22, 3306} {
		g.GinkgoWriter.Printf("expecting deny from default to %s:%d (unauthorized port)\n", authServerIP, port)
		expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, authServerIP, port, false)
	}

	g.By("Testing cross-namespace traffic: oauth-server -> auth-operator (best-effort)")
	g.GinkgoWriter.Printf("checking connectivity from openshift-authentication to %s:8443\n", authOperatorIP)
	logConnectivityBestEffort(kubeClient, "openshift-authentication", map[string]string{"app": "oauth-openshift"}, authOperatorIP, 8443)
}

func netexecPod(name, namespace string, labels map[string]string, port int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
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

func createServerPod(kubeClient kubernetes.Interface, namespace, name string, labels map[string]string, port int32) (string, func()) {
	g.GinkgoHelper()

	g.GinkgoWriter.Printf("creating server pod %s/%s port=%d labels=%v\n", namespace, name, port, labels)
	pod := netexecPod(name, namespace, labels, port)
	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(kubeClient, namespace, name)).NotTo(o.HaveOccurred())

	created, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(created.Status.PodIP).NotTo(o.BeEmpty())
	g.GinkgoWriter.Printf("server pod %s/%s ip=%s\n", namespace, name, created.Status.PodIP)

	return created.Status.PodIP, func() {
		g.GinkgoWriter.Printf("deleting server pod %s/%s\n", namespace, name)
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}
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

func expectConnectivity(kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	err := wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		succeeded, err := runConnectivityCheck(kubeClient, namespace, clientLabels, serverIP, port)
		if err != nil {
			return false, err
		}
		return succeeded == shouldSucceed, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("connectivity %s/%s:%d expected=%t\n", namespace, serverIP, port, shouldSucceed)
}

func logConnectivityBestEffort(kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32) {
	g.GinkgoHelper()

	succeeded, err := runConnectivityCheck(kubeClient, namespace, clientLabels, serverIP, port)
	if err != nil {
		g.GinkgoWriter.Printf("connectivity %s/%s:%d error: %v\n", namespace, serverIP, port, err)
		return
	}
	g.GinkgoWriter.Printf("connectivity %s/%s:%d succeeded=%t (best-effort)\n", namespace, serverIP, port, succeeded)
}

func runConnectivityCheck(kubeClient kubernetes.Interface, namespace string, labels map[string]string, serverIP string, port int32) (bool, error) {
	g.GinkgoHelper()

	name := fmt.Sprintf("np-client-%s", rand.String(5))
	g.GinkgoWriter.Printf("creating client pod %s/%s to connect %s:%d\n", namespace, name, serverIP, port)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
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
					Command: []string{"/agnhost"},
					Args: []string{
						"connect",
						"--protocol=tcp",
						"--timeout=5s",
						fmt.Sprintf("%s:%d", serverIP, port),
					},
				},
			},
		},
	}

	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	defer func() {
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}()

	if err := waitForPodCompletion(kubeClient, namespace, name); err != nil {
		return false, err
	}
	completed, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(completed.Status.ContainerStatuses) == 0 {
		return false, fmt.Errorf("no container status recorded for pod %s", name)
	}
	exitCode := completed.Status.ContainerStatuses[0].State.Terminated.ExitCode
	g.GinkgoWriter.Printf("client pod %s/%s exitCode=%d\n", namespace, name, exitCode)
	return exitCode == 0, nil
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
			continue
		}
		if p.Port.Type == intstr.Int && p.Port.IntVal == port {
			return true
		}
	}
	return false
}

func egressAllowsNamespace(policy *networkingv1.NetworkPolicy, namespace string, port int32) bool {
	for _, rule := range policy.Spec.Egress {
		if !ruleAllowsPort(rule.Ports, port) {
			continue
		}
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if peer.NamespaceSelector != nil && nsMatch(peer.NamespaceSelector, namespace) {
				return true
			}
		}
	}
	return false
}

func boolToAllowDeny(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func waitForPodReady(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
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

func waitForPodCompletion(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed, nil
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
