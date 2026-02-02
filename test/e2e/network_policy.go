package e2e

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	test "github.com/openshift/cluster-authentication-operator/test/library"
)

const (
	authNamespace            = "openshift-authentication"
	oauthAPINamespace        = "openshift-oauth-apiserver"
	defaultDenyAllPolicyName = "default-deny-all"
	oauthServerPolicyName    = "oauth-server-networkpolicy"
	oauthAPIServerPolicyName = "oauth-apiserver-networkpolicy"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Operator][NetworkPolicy][Serial] should ensure auth NetworkPolicies are defined", func() {
		testAuthNetworkPolicies()
	})
	g.It("[Operator][NetworkPolicy][Serial] should restore auth NetworkPolicies after delete or mutation", func() {
		testAuthNetworkPolicyReconcile()
	})
})

func testAuthNetworkPolicies() {
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeConfig := test.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for authentication ClusterOperator to be stable")
	err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(g.GinkgoTB(), configClient, "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Validating NetworkPolicies in openshift-authentication")
	authDefaultDeny := getNetworkPolicy(ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	logNetworkPolicySummary("auth/default-deny-all", authDefaultDeny)
	requireDefaultDenyAll(authDefaultDeny)

	authPolicy := getNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	logNetworkPolicySummary("auth/oauth-server-networkpolicy", authPolicy)
	requirePodSelectorLabel(authPolicy, "app", "oauth-openshift")
	requireIngressPort(authPolicy, corev1.ProtocolTCP, 6443)
	requireIngressFromNamespace(authPolicy, 6443, "openshift-monitoring")
	requireIngressFromNamespace(authPolicy, 6443, "openshift-ingress")
	requireIngressFromNamespace(authPolicy, 6443, "openshift-authentication-operator")
	requireIngressAllowAll(authPolicy, 6443)
	requireEgressPort(authPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(authPolicy, corev1.ProtocolUDP, 5353)
	requireEgressPort(authPolicy, corev1.ProtocolTCP, 8443)

	g.By("Validating NetworkPolicies in openshift-oauth-apiserver")
	oauthDefaultDeny := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	logNetworkPolicySummary("oauth-apiserver/default-deny-all", oauthDefaultDeny)
	requireDefaultDenyAll(oauthDefaultDeny)

	oauthPolicy := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	logNetworkPolicySummary("oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	requirePodSelectorLabel(oauthPolicy, "app", "openshift-oauth-apiserver")
	requireIngressPort(oauthPolicy, corev1.ProtocolTCP, 8443)
	requireIngressFromNamespace(oauthPolicy, 8443, "openshift-monitoring")
	requireIngressFromNamespace(oauthPolicy, 8443, "openshift-authentication")
	requireIngressFromNamespace(oauthPolicy, 8443, "openshift-authentication-operator")
	requireIngressAllowAll(oauthPolicy, 8443)
	requireEgressPort(oauthPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(oauthPolicy, corev1.ProtocolUDP, 5353)
	requireEgressPort(oauthPolicy, corev1.ProtocolTCP, 2379)

	g.By("Verifying pods are ready in auth namespaces")
	waitForPodsReadyByLabel(ctx, kubeClient, authNamespace, "app=oauth-openshift")
	waitForPodsReadyByLabel(ctx, kubeClient, oauthAPINamespace, "app=openshift-oauth-apiserver")
}

func testAuthNetworkPolicyReconcile() {
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeConfig := test.NewClientConfigForTest(g.GinkgoTB())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for authentication ClusterOperator to be stable")
	err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(g.GinkgoTB(), configClient, "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deleting policies and waiting for restoration")
	restoreNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)

	g.By("Mutating policies and waiting for reconciliation")
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)

	g.By("Checking NetworkPolicy-related events")
	waitForNetworkPolicyEvent(ctx, kubeClient, "openshift-authentication-operator", oauthServerPolicyName)
}

func getNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) *networkingv1.NetworkPolicy {
	g.GinkgoHelper()
	policy, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get NetworkPolicy %s/%s", namespace, name)
	return policy
}

func requireDefaultDenyAll(policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	if len(policy.Spec.PodSelector.MatchLabels) != 0 || len(policy.Spec.PodSelector.MatchExpressions) != 0 {
		g.Fail(fmt.Sprintf("%s/%s: expected empty podSelector", policy.Namespace, policy.Name))
	}

	policyTypes := sets.NewString()
	for _, policyType := range policy.Spec.PolicyTypes {
		policyTypes.Insert(string(policyType))
	}
	if !policyTypes.Has(string(networkingv1.PolicyTypeIngress)) || !policyTypes.Has(string(networkingv1.PolicyTypeEgress)) {
		g.Fail(fmt.Sprintf("%s/%s: expected both Ingress and Egress policyTypes, got %v", policy.Namespace, policy.Name, policy.Spec.PolicyTypes))
	}
}

func requirePodSelectorLabel(policy *networkingv1.NetworkPolicy, key, value string) {
	g.GinkgoHelper()
	actual, ok := policy.Spec.PodSelector.MatchLabels[key]
	if !ok || actual != value {
		g.Fail(fmt.Sprintf("%s/%s: expected podSelector %s=%s, got %v", policy.Namespace, policy.Name, key, value, policy.Spec.PodSelector.MatchLabels))
	}
}

func requireIngressPort(policy *networkingv1.NetworkPolicy, protocol corev1.Protocol, port int32) {
	g.GinkgoHelper()
	if !hasPortInIngress(policy.Spec.Ingress, protocol, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected ingress port %s/%d", policy.Namespace, policy.Name, protocol, port))
	}
}

func requireIngressFromNamespace(policy *networkingv1.NetworkPolicy, port int32, namespace string) {
	g.GinkgoHelper()
	if !hasIngressFromNamespace(policy.Spec.Ingress, port, namespace) {
		g.Fail(fmt.Sprintf("%s/%s: expected ingress from namespace %s on port %d", policy.Namespace, policy.Name, namespace, port))
	}
}

func requireIngressAllowAll(policy *networkingv1.NetworkPolicy, port int32) {
	g.GinkgoHelper()
	if !hasIngressAllowAll(policy.Spec.Ingress, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected ingress allow-all on port %d", policy.Namespace, policy.Name, port))
	}
}

func requireEgressPort(policy *networkingv1.NetworkPolicy, protocol corev1.Protocol, port int32) {
	g.GinkgoHelper()
	if !hasPortInEgress(policy.Spec.Egress, protocol, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected egress port %s/%d", policy.Namespace, policy.Name, protocol, port))
	}
}

func hasPortInIngress(rules []networkingv1.NetworkPolicyIngressRule, protocol corev1.Protocol, port int32) bool {
	for _, rule := range rules {
		if hasPort(rule.Ports, protocol, port) {
			return true
		}
	}
	return false
}

func hasPortInEgress(rules []networkingv1.NetworkPolicyEgressRule, protocol corev1.Protocol, port int32) bool {
	for _, rule := range rules {
		if hasPort(rule.Ports, protocol, port) {
			return true
		}
	}
	return false
}

func hasPort(ports []networkingv1.NetworkPolicyPort, protocol corev1.Protocol, port int32) bool {
	for _, p := range ports {
		if p.Port == nil || p.Port.IntValue() != int(port) {
			continue
		}
		if p.Protocol == nil || *p.Protocol == protocol {
			return true
		}
	}
	return false
}

func hasIngressFromNamespace(rules []networkingv1.NetworkPolicyIngressRule, port int32, namespace string) bool {
	for _, rule := range rules {
		if !hasPort(rule.Ports, corev1.ProtocolTCP, port) {
			continue
		}
		for _, peer := range rule.From {
			if namespaceSelectorMatches(peer.NamespaceSelector, namespace) {
				return true
			}
		}
	}
	return false
}

func hasIngressAllowAll(rules []networkingv1.NetworkPolicyIngressRule, port int32) bool {
	for _, rule := range rules {
		if !hasPort(rule.Ports, corev1.ProtocolTCP, port) {
			continue
		}
		if len(rule.From) == 0 {
			return true
		}
	}
	return false
}

func namespaceSelectorMatches(selector *metav1.LabelSelector, namespace string) bool {
	if selector == nil {
		return false
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
		for _, value := range expr.Values {
			if value == namespace {
				return true
			}
		}
	}
	return false
}

func restoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	g.GinkgoHelper()
	o.Expect(client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})).NotTo(o.HaveOccurred())
	err := wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		_, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s to be restored", namespace, name)
}

func mutateAndRestoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	g.GinkgoHelper()
	original := getNetworkPolicy(ctx, client, namespace, name)
	patch := []byte(`{"spec":{"podSelector":{"matchLabels":{"np-reconcile":"mutated"}}}}`)
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		current := getNetworkPolicy(ctx, client, namespace, name)
		return equality.Semantic.DeepEqual(original.Spec, current.Spec), nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s spec to be restored", namespace, name)
}

func waitForPodsReadyByLabel(ctx context.Context, client kubernetes.Interface, namespace, labelSelector string) {
	g.GinkgoHelper()
	err := wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			return false, err
		}
		if len(pods.Items) == 0 {
			return false, nil
		}
		for _, pod := range pods.Items {
			if !isPodReady(&pod) {
				return false, nil
			}
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for pods in %s with selector %s to be ready", namespace, labelSelector)
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func waitForNetworkPolicyEvent(ctx context.Context, client kubernetes.Interface, namespace, policyName string) {
	g.GinkgoHelper()
	err := wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		for _, event := range events.Items {
			if event.InvolvedObject.Kind == "NetworkPolicy" && event.InvolvedObject.Name == policyName {
				return true, nil
			}
			if event.Message != "" && (event.InvolvedObject.Name == policyName || event.InvolvedObject.Kind == "NetworkPolicy") {
				return true, nil
			}
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy event for %s/%s", namespace, policyName)
}

func logNetworkPolicySummary(label string, policy *networkingv1.NetworkPolicy) {
	g.GinkgoWriter.Printf("networkpolicy %s namespace=%s name=%s podSelector=%v policyTypes=%v ingress=%d egress=%d\n",
		label,
		policy.Namespace,
		policy.Name,
		policy.Spec.PodSelector.MatchLabels,
		policy.Spec.PolicyTypes,
		len(policy.Spec.Ingress),
		len(policy.Spec.Egress),
	)
}
