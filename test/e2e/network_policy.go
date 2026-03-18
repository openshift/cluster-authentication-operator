package e2e

import (
	"context"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
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

	reconcileTimeout = 10 * time.Minute
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[NetworkPolicy][Disruptive][Serial] should ensure auth NetworkPolicies are defined", func() {
		testAuthNetworkPolicies()
	})
	g.It("[NetworkPolicy][Disruptive][Serial] should restore auth NetworkPolicies after delete or mutation[Timeout:30m]", func() {
		testAuthNetworkPolicyReconcile()
	})
})

func testAuthNetworkPolicies() {
	t := g.GinkgoTB()
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeConfig := test.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for authentication ClusterOperator to be stable")
	err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient, "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Validating NetworkPolicies in openshift-authentication")
	authDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	LogNetworkPolicySummary(t, "auth/default-deny-all", authDefaultDeny)
	LogNetworkPolicyDetails(t, "auth/default-deny-all", authDefaultDeny)
	RequireDefaultDenyAll(t, authDefaultDeny)

	authPolicy := GetNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName)
	LogNetworkPolicySummary(t, "auth/oauth-server-networkpolicy", authPolicy)
	LogNetworkPolicyDetails(t, "auth/oauth-server-networkpolicy", authPolicy)
	RequirePodSelectorLabel(t, authPolicy, "app", "oauth-openshift")
	RequireIngressPort(t, authPolicy, corev1.ProtocolTCP, 6443)
	LogIngressFromNamespaceOptional(t, authPolicy, 6443, "openshift-monitoring")
	RequireIngressFromNamespaceOrPolicyGroup(t, authPolicy, 6443, "openshift-ingress", "policy-group.network.openshift.io/ingress")
	RequireIngressFromNamespace(t, authPolicy, 6443, authOperatorNamespace)
	RequireEgressPort(t, authPolicy, corev1.ProtocolTCP, 5353)
	RequireEgressPort(t, authPolicy, corev1.ProtocolUDP, 5353)
	RequireEgressPort(t, authPolicy, corev1.ProtocolTCP, 8443)
	LogIngressHostNetworkOrAllowAll(t, authPolicy, 6443)
	LogEgressAllowAllTCP(t, authPolicy)

	g.By("Validating NetworkPolicies in openshift-oauth-apiserver")
	oauthDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	LogNetworkPolicySummary(t, "oauth-apiserver/default-deny-all", oauthDefaultDeny)
	LogNetworkPolicyDetails(t, "oauth-apiserver/default-deny-all", oauthDefaultDeny)
	RequireDefaultDenyAll(t, oauthDefaultDeny)

	oauthPolicy := GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	LogNetworkPolicySummary(t, "oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	LogNetworkPolicyDetails(t, "oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	RequirePodSelectorLabel(t, oauthPolicy, "app", "openshift-oauth-apiserver")
	RequireIngressPort(t, oauthPolicy, corev1.ProtocolTCP, 8443)
	LogIngressFromNamespaceOptional(t, oauthPolicy, 8443, "openshift-monitoring")
	RequireIngressFromNamespace(t, oauthPolicy, 8443, "openshift-authentication")
	RequireIngressFromNamespace(t, oauthPolicy, 8443, authOperatorNamespace)
	RequireEgressPort(t, oauthPolicy, corev1.ProtocolTCP, 5353)
	RequireEgressPort(t, oauthPolicy, corev1.ProtocolUDP, 5353)
	RequireEgressPort(t, oauthPolicy, corev1.ProtocolTCP, 2379)
	LogIngressHostNetworkOrAllowAll(t, oauthPolicy, 8443)
	LogEgressAllowAllTCP(t, oauthPolicy)

	g.By("Validating NetworkPolicies in openshift-authentication-operator")
	operatorDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)
	LogNetworkPolicySummary(t, "auth-operator/default-deny-all", operatorDefaultDeny)
	LogNetworkPolicyDetails(t, "auth-operator/default-deny-all", operatorDefaultDeny)
	RequireDefaultDenyAll(t, operatorDefaultDeny)

	operatorPolicy := GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	LogNetworkPolicySummary(t, "auth-operator/"+authOperatorPolicyName, operatorPolicy)
	LogNetworkPolicyDetails(t, "auth-operator/"+authOperatorPolicyName, operatorPolicy)
	RequirePodSelectorLabel(t, operatorPolicy, "app", "authentication-operator")
	RequireIngressPort(t, operatorPolicy, corev1.ProtocolTCP, 8443)
	LogIngressFromNamespaceOptional(t, operatorPolicy, 8443, "openshift-monitoring")
	RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 5353)
	RequireEgressPort(t, operatorPolicy, corev1.ProtocolUDP, 5353)
	RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 6443)
	RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 8443)
	LogEgressAllowAllTCP(t, operatorPolicy)

	g.By("Verifying pods are ready in auth namespaces")
	WaitForPodsReadyByLabel(t, ctx, kubeClient, authNamespace, "app=oauth-openshift")
	WaitForPodsReadyByLabel(t, ctx, kubeClient, oauthAPINamespace, "app=openshift-oauth-apiserver")
	WaitForPodsReadyByLabel(t, ctx, kubeClient, authOperatorNamespace, "app=authentication-operator")
}

func testAuthNetworkPolicyReconcile() {
	t := g.GinkgoTB()
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeConfig := test.NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for authentication ClusterOperator to be stable")
	err = test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient, "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Capturing expected NetworkPolicy specs")
	expectedAuthPolicy := GetNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName)
	expectedOAuthAPIPolicy := GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	expectedAuthOperatorPolicy := GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	expectedAuthDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	expectedOAuthAPIDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	expectedAuthOperatorDefaultDeny := GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)

	g.By("Deleting main policies and waiting for restoration")
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthPolicy, reconcileTimeout)
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedOAuthAPIPolicy, reconcileTimeout)
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthOperatorPolicy, reconcileTimeout)

	g.By("Deleting default-deny-all policies and waiting for restoration")
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthDefaultDeny, reconcileTimeout)
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedOAuthAPIDefaultDeny, reconcileTimeout)
	RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthOperatorDefaultDeny, reconcileTimeout)

	g.By("Mutating main policies and waiting for reconciliation")
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName, reconcileTimeout)
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName, reconcileTimeout)
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName, reconcileTimeout)

	g.By("Mutating default-deny-all policies and waiting for reconciliation")
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName, reconcileTimeout)
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName, reconcileTimeout)
	MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName, reconcileTimeout)

	g.By("Checking NetworkPolicy-related events (best-effort)")
	LogNetworkPolicyEvents(t, ctx, kubeClient, []string{authOperatorNamespace, authNamespace, oauthAPINamespace}, oauthServerPolicyName)
}
