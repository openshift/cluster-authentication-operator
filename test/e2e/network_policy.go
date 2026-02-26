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
	authOperatorNamespace    = "openshift-authentication-operator"
	defaultDenyAllPolicyName = "default-deny-all"
	oauthServerPolicyName    = "oauth-server-networkpolicy"
	oauthAPIServerPolicyName = "oauth-apiserver-networkpolicy"
	authOperatorPolicyName   = "authentication-operator-networkpolicy"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Operator][NetworkPolicy] should ensure auth NetworkPolicies are defined", func() {
		testAuthNetworkPolicies()
	})
	g.It("[Operator][NetworkPolicy] should restore auth NetworkPolicies after delete or mutation[Timeout:30m]", func() {
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
	logNetworkPolicyDetails("auth/default-deny-all", authDefaultDeny)
	requireDefaultDenyAll(authDefaultDeny)

	authPolicy := getNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	logNetworkPolicySummary("auth/oauth-server-networkpolicy", authPolicy)
	logNetworkPolicyDetails("auth/oauth-server-networkpolicy", authPolicy)
	requirePodSelectorLabel(authPolicy, "app", "oauth-openshift")
	requireIngressPort(authPolicy, corev1.ProtocolTCP, 6443)
	logIngressFromNamespaceOptional(authPolicy, 6443, "openshift-monitoring")
	requireIngressFromNamespaceOrPolicyGroup(authPolicy, 6443, "openshift-ingress", "policy-group.network.openshift.io/ingress")
	requireIngressFromNamespace(authPolicy, 6443, authOperatorNamespace)
	requireEgressPort(authPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(authPolicy, corev1.ProtocolUDP, 5353)
	requireEgressPort(authPolicy, corev1.ProtocolTCP, 8443)
	logIngressHostNetworkOrAllowAll(authPolicy, 6443)
	logEgressAllowAllTCP(authPolicy)

	g.By("Validating NetworkPolicies in openshift-oauth-apiserver")
	oauthDefaultDeny := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	logNetworkPolicySummary("oauth-apiserver/default-deny-all", oauthDefaultDeny)
	logNetworkPolicyDetails("oauth-apiserver/default-deny-all", oauthDefaultDeny)
	requireDefaultDenyAll(oauthDefaultDeny)

	oauthPolicy := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	logNetworkPolicySummary("oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	logNetworkPolicyDetails("oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	requirePodSelectorLabel(oauthPolicy, "app", "openshift-oauth-apiserver")
	requireIngressPort(oauthPolicy, corev1.ProtocolTCP, 8443)
	logIngressFromNamespaceOptional(oauthPolicy, 8443, "openshift-monitoring")
	requireIngressFromNamespace(oauthPolicy, 8443, "openshift-authentication")
	requireIngressFromNamespace(oauthPolicy, 8443, authOperatorNamespace)
	requireEgressPort(oauthPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(oauthPolicy, corev1.ProtocolUDP, 5353)
	requireEgressPort(oauthPolicy, corev1.ProtocolTCP, 2379)
	logIngressHostNetworkOrAllowAll(oauthPolicy, 8443)
	logEgressAllowAllTCP(oauthPolicy)

	g.By("Validating NetworkPolicies in openshift-authentication-operator")
	operatorDefaultDeny := getNetworkPolicy(ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)
	logNetworkPolicySummary("auth-operator/default-deny-all", operatorDefaultDeny)
	logNetworkPolicyDetails("auth-operator/default-deny-all", operatorDefaultDeny)
	requireDefaultDenyAll(operatorDefaultDeny)

	operatorPolicy := getNetworkPolicy(ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	logNetworkPolicySummary("auth-operator/"+authOperatorPolicyName, operatorPolicy)
	logNetworkPolicyDetails("auth-operator/"+authOperatorPolicyName, operatorPolicy)
	requirePodSelectorLabel(operatorPolicy, "app", "authentication-operator")
	requireIngressPort(operatorPolicy, corev1.ProtocolTCP, 8443)
	logIngressFromNamespaceOptional(operatorPolicy, 8443, "openshift-monitoring")
	requireEgressPort(operatorPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(operatorPolicy, corev1.ProtocolUDP, 5353)
	requireEgressPort(operatorPolicy, corev1.ProtocolTCP, 6443)
	requireEgressPort(operatorPolicy, corev1.ProtocolTCP, 8443)
	logEgressAllowAllTCP(operatorPolicy)

	g.By("Verifying pods are ready in auth namespaces")
	waitForPodsReadyByLabel(ctx, kubeClient, authNamespace, "app=oauth-openshift")
	waitForPodsReadyByLabel(ctx, kubeClient, oauthAPINamespace, "app=openshift-oauth-apiserver")
	waitForPodsReadyByLabel(ctx, kubeClient, authOperatorNamespace, "app=authentication-operator")
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

	g.By("Capturing expected NetworkPolicy specs")
	expectedAuthPolicy := getNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	expectedOAuthAPIPolicy := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	expectedAuthOperatorPolicy := getNetworkPolicy(ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	expectedAuthDefaultDeny := getNetworkPolicy(ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	expectedOAuthAPIDefaultDeny := getNetworkPolicy(ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	expectedAuthOperatorDefaultDeny := getNetworkPolicy(ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)

	g.By("Deleting main policies and waiting for restoration")
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", authNamespace, oauthServerPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedAuthPolicy)
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", oauthAPINamespace, oauthAPIServerPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedOAuthAPIPolicy)
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", authOperatorNamespace, authOperatorPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedAuthOperatorPolicy)

	g.By("Deleting default-deny-all policies and waiting for restoration")
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", authNamespace, defaultDenyAllPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedAuthDefaultDeny)
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", oauthAPINamespace, defaultDenyAllPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedOAuthAPIDefaultDeny)
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", authOperatorNamespace, defaultDenyAllPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, expectedAuthOperatorDefaultDeny)

	g.By("Mutating main policies and waiting for reconciliation")
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", authNamespace, oauthServerPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, authNamespace, oauthServerPolicyName)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", oauthAPINamespace, oauthAPIServerPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", authOperatorNamespace, authOperatorPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)

	g.By("Mutating default-deny-all policies and waiting for reconciliation")
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", authNamespace, defaultDenyAllPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", oauthAPINamespace, defaultDenyAllPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", authOperatorNamespace, defaultDenyAllPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)

	g.By("Checking NetworkPolicy-related events (best-effort)")
	logNetworkPolicyEvents(ctx, kubeClient, []string{"openshift-authentication-operator", authNamespace, oauthAPINamespace}, oauthServerPolicyName)
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

func logIngressFromNamespaceOptional(policy *networkingv1.NetworkPolicy, port int32, namespace string) {
	g.GinkgoHelper()
	if hasIngressFromNamespace(policy.Spec.Ingress, port, namespace) {
		g.GinkgoWriter.Printf("networkpolicy %s/%s: ingress from namespace %s present on port %d\n", policy.Namespace, policy.Name, namespace, port)
		return
	}
	g.GinkgoWriter.Printf("networkpolicy %s/%s: no ingress from namespace %s on port %d\n", policy.Namespace, policy.Name, namespace, port)
}

func requireIngressFromNamespaceOrPolicyGroup(policy *networkingv1.NetworkPolicy, port int32, namespace, policyGroupLabelKey string) {
	g.GinkgoHelper()
	if hasIngressFromNamespace(policy.Spec.Ingress, port, namespace) {
		return
	}
	if hasIngressFromPolicyGroup(policy.Spec.Ingress, port, policyGroupLabelKey) {
		return
	}
	g.Fail(fmt.Sprintf("%s/%s: expected ingress from namespace %s or policy-group %s on port %d", policy.Namespace, policy.Name, namespace, policyGroupLabelKey, port))
}

func requireIngressAllowAll(policy *networkingv1.NetworkPolicy, port int32) {
	g.GinkgoHelper()
	if !hasIngressAllowAll(policy.Spec.Ingress, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected ingress allow-all on port %d", policy.Namespace, policy.Name, port))
	}
}

func logIngressHostNetworkOrAllowAll(policy *networkingv1.NetworkPolicy, port int32) {
	g.GinkgoHelper()
	if hasIngressAllowAll(policy.Spec.Ingress, port) {
		g.GinkgoWriter.Printf("networkpolicy %s/%s: ingress allow-all present on port %d\n", policy.Namespace, policy.Name, port)
		return
	}
	if hasIngressFromPolicyGroup(policy.Spec.Ingress, port, "policy-group.network.openshift.io/host-network") {
		g.GinkgoWriter.Printf("networkpolicy %s/%s: ingress host-network policy-group present on port %d\n", policy.Namespace, policy.Name, port)
		return
	}
	g.GinkgoWriter.Printf("networkpolicy %s/%s: no ingress allow-all/host-network rule on port %d\n", policy.Namespace, policy.Name, port)
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

func hasIngressFromPolicyGroup(rules []networkingv1.NetworkPolicyIngressRule, port int32, policyGroupLabelKey string) bool {
	for _, rule := range rules {
		if !hasPort(rule.Ports, corev1.ProtocolTCP, port) {
			continue
		}
		for _, peer := range rule.From {
			if peer.NamespaceSelector == nil || peer.NamespaceSelector.MatchLabels == nil {
				continue
			}
			if _, ok := peer.NamespaceSelector.MatchLabels[policyGroupLabelKey]; ok {
				return true
			}
		}
	}
	return false
}

func logEgressAllowAllTCP(policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	if hasEgressAllowAllTCP(policy.Spec.Egress) {
		g.GinkgoWriter.Printf("networkpolicy %s/%s: egress allow-all TCP rule present\n", policy.Namespace, policy.Name)
		return
	}
	g.GinkgoWriter.Printf("networkpolicy %s/%s: no egress allow-all TCP rule\n", policy.Namespace, policy.Name)
}

func hasEgressAllowAllTCP(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, rule := range rules {
		if len(rule.To) != 0 {
			continue
		}
		if hasAnyTCPPort(rule.Ports) {
			return true
		}
	}
	return false
}

func hasAnyTCPPort(ports []networkingv1.NetworkPolicyPort) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Protocol != nil && *p.Protocol != corev1.ProtocolTCP {
			continue
		}
		return true
	}
	return false
}

func restoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, expected *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	namespace := expected.Namespace
	name := expected.Name
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", namespace, name)
	o.Expect(client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})).NotTo(o.HaveOccurred())
	err := wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		current, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return equality.Semantic.DeepEqual(expected.Spec, current.Spec), nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s spec to be restored", namespace, name)
	g.GinkgoWriter.Printf("NetworkPolicy %s/%s spec restored after delete\n", namespace, name)
}

func mutateAndRestoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	g.GinkgoHelper()
	original := getNetworkPolicy(ctx, client, namespace, name)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s (podSelector override)\n", namespace, name)
	patch := []byte(`{"spec":{"podSelector":{"matchLabels":{"np-reconcile":"mutated"}}}}`)
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		current := getNetworkPolicy(ctx, client, namespace, name)
		return equality.Semantic.DeepEqual(original.Spec, current.Spec), nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s spec to be restored", namespace, name)
	g.GinkgoWriter.Printf("NetworkPolicy %s/%s spec restored\n", namespace, name)
}

func waitForPodsReadyByLabel(ctx context.Context, client kubernetes.Interface, namespace, labelSelector string) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("waiting for pods ready in %s with selector %s\n", namespace, labelSelector)
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

func logNetworkPolicyEvents(ctx context.Context, client kubernetes.Interface, namespaces []string, policyName string) {
	g.GinkgoHelper()
	found := false
	_ = wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		for _, namespace := range namespaces {
			events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				g.GinkgoWriter.Printf("unable to list events in %s: %v\n", namespace, err)
				continue
			}
			for _, event := range events.Items {
				if event.InvolvedObject.Kind == "NetworkPolicy" && event.InvolvedObject.Name == policyName {
					g.GinkgoWriter.Printf("event in %s: %s %s %s\n", namespace, event.Type, event.Reason, event.Message)
					found = true
				}
				if event.Message != "" && (event.InvolvedObject.Name == policyName || event.InvolvedObject.Kind == "NetworkPolicy") {
					g.GinkgoWriter.Printf("event in %s: %s %s %s\n", namespace, event.Type, event.Reason, event.Message)
					found = true
				}
			}
		}
		if found {
			return true, nil
		}
		g.GinkgoWriter.Printf("no NetworkPolicy events yet for %s (namespaces: %v)\n", policyName, namespaces)
		return false, nil
	})
	if !found {
		g.GinkgoWriter.Printf("no NetworkPolicy events observed for %s (best-effort)\n", policyName)
	}
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

func logNetworkPolicyDetails(label string, policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("networkpolicy %s details:\n", label)
	g.GinkgoWriter.Printf("  podSelector=%v policyTypes=%v\n", policy.Spec.PodSelector.MatchLabels, policy.Spec.PolicyTypes)
	for i, rule := range policy.Spec.Ingress {
		g.GinkgoWriter.Printf("  ingress[%d]: ports=%s from=%s\n", i, formatPorts(rule.Ports), formatPeers(rule.From))
	}
	for i, rule := range policy.Spec.Egress {
		g.GinkgoWriter.Printf("  egress[%d]: ports=%s to=%s\n", i, formatPorts(rule.Ports), formatPeers(rule.To))
	}
}

func formatPorts(ports []networkingv1.NetworkPolicyPort) string {
	if len(ports) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		proto := "TCP"
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		if p.Port == nil {
			out = append(out, fmt.Sprintf("%s:any", proto))
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", proto, p.Port.String()))
	}
	return fmt.Sprintf("[%s]", joinStrings(out))
}

func formatPeers(peers []networkingv1.NetworkPolicyPeer) string {
	if len(peers) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(peers))
	for _, peer := range peers {
		ns := formatSelector(peer.NamespaceSelector)
		pod := formatSelector(peer.PodSelector)
		if ns == "" && pod == "" {
			out = append(out, "{}")
			continue
		}
		out = append(out, fmt.Sprintf("ns=%s pod=%s", ns, pod))
	}
	return fmt.Sprintf("[%s]", joinStrings(out))
}

func formatSelector(sel *metav1.LabelSelector) string {
	if sel == nil {
		return ""
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return "{}"
	}
	return fmt.Sprintf("labels=%v exprs=%v", sel.MatchLabels, sel.MatchExpressions)
}

func joinStrings(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for i := 1; i < len(items); i++ {
		out += ", " + items[i]
	}
	return out
}
