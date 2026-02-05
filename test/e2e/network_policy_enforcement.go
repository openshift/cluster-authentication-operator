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
})

func testGenericNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := e2e.NewTestNamespaceBuilder("np-enforcement-").Create(g.GinkgoTB(), kubeClient.CoreV1().Namespaces())
	defer func() {
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
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
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
	allowedServerIP, cleanupAllowed := createServerPod(kubeClient, namespace, "np-auth-allowed", serverLabels, 6443)
	defer cleanupAllowed()
	deniedServerIP, cleanupDenied := createServerPod(kubeClient, namespace, "np-auth-denied", serverLabels, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 6443")
	expectConnectivity(kubeClient, namespace, clientLabels, allowedServerIP, 6443, true)
	g.By("Verifying denied port 12345")
	expectConnectivity(kubeClient, namespace, clientLabels, deniedServerIP, 12345, false)
}

func testOAuthAPIServerNetworkPolicyEnforcement() {
	kubeConfig := e2e.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	serverNamespace := "openshift-oauth-apiserver"
	clientNamespace := "openshift-authentication"
	clientLabels := map[string]string{"app": "oauth-openshift"}

	g.By("Creating oauth-apiserver test pods for allow/deny checks")
	allowedServerIP, cleanupAllowed := createServerPod(kubeClient, serverNamespace, "np-oauth-api-allowed", map[string]string{"app": "openshift-oauth-apiserver"}, 8443)
	defer cleanupAllowed()
	deniedServerIP, cleanupDenied := createServerPod(kubeClient, serverNamespace, "np-oauth-api-denied", map[string]string{"app": "openshift-oauth-apiserver"}, 12345)
	defer cleanupDenied()

	g.By("Verifying allowed port 8443")
	expectConnectivity(kubeClient, clientNamespace, clientLabels, allowedServerIP, 8443, true)
	g.By("Verifying denied port 12345")
	expectConnectivity(kubeClient, clientNamespace, clientLabels, deniedServerIP, 12345, false)
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

	pod := netexecPod(name, namespace, labels, port)
	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(kubeClient, namespace, name)).NotTo(o.HaveOccurred())

	created, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(created.Status.PodIP).NotTo(o.BeEmpty())

	return created.Status.PodIP, func() {
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
