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
	np "github.com/openshift/library-go/test/library/networkpolicy"
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
	authDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	np.LogNetworkPolicySummary(t, "auth/default-deny-all", authDefaultDeny)
	np.LogNetworkPolicyDetails(t, "auth/default-deny-all", authDefaultDeny)
	np.RequireDefaultDenyAll(t, authDefaultDeny)

	authPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName)
	np.LogNetworkPolicySummary(t, "auth/oauth-server-networkpolicy", authPolicy)
	np.LogNetworkPolicyDetails(t, "auth/oauth-server-networkpolicy", authPolicy)
	np.RequirePodSelectorLabel(t, authPolicy, "app", "oauth-openshift")
	np.RequireIngressPort(t, authPolicy, corev1.ProtocolTCP, 6443)
	np.LogIngressFromNamespaceOptional(t, authPolicy, 6443, "openshift-monitoring")
	np.RequireIngressFromNamespaceOrPolicyGroup(t, authPolicy, 6443, "openshift-ingress", "policy-group.network.openshift.io/ingress")
	np.RequireIngressFromNamespace(t, authPolicy, 6443, authOperatorNamespace)
	np.RequireEgressPort(t, authPolicy, corev1.ProtocolTCP, 5353)
	np.RequireEgressPort(t, authPolicy, corev1.ProtocolUDP, 5353)
	np.RequireEgressPort(t, authPolicy, corev1.ProtocolTCP, 8443)
	np.LogIngressHostNetworkOrAllowAll(t, authPolicy, 6443)
	np.LogEgressAllowAllTCP(t, authPolicy)

	g.By("Validating NetworkPolicies in openshift-oauth-apiserver")
	oauthDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	np.LogNetworkPolicySummary(t, "oauth-apiserver/default-deny-all", oauthDefaultDeny)
	np.LogNetworkPolicyDetails(t, "oauth-apiserver/default-deny-all", oauthDefaultDeny)
	np.RequireDefaultDenyAll(t, oauthDefaultDeny)

	oauthPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	np.LogNetworkPolicySummary(t, "oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	np.LogNetworkPolicyDetails(t, "oauth-apiserver/oauth-apiserver-networkpolicy", oauthPolicy)
	np.RequirePodSelectorLabel(t, oauthPolicy, "app", "openshift-oauth-apiserver")
	np.RequireIngressPort(t, oauthPolicy, corev1.ProtocolTCP, 8443)
	np.LogIngressFromNamespaceOptional(t, oauthPolicy, 8443, "openshift-monitoring")
	np.RequireIngressFromNamespace(t, oauthPolicy, 8443, "openshift-authentication")
	np.RequireIngressFromNamespace(t, oauthPolicy, 8443, authOperatorNamespace)
	np.RequireEgressPort(t, oauthPolicy, corev1.ProtocolTCP, 5353)
	np.RequireEgressPort(t, oauthPolicy, corev1.ProtocolUDP, 5353)
	np.RequireEgressPort(t, oauthPolicy, corev1.ProtocolTCP, 2379)
	np.LogIngressHostNetworkOrAllowAll(t, oauthPolicy, 8443)
	np.LogEgressAllowAllTCP(t, oauthPolicy)

	g.By("Validating NetworkPolicies in openshift-authentication-operator")
	operatorDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)
	np.LogNetworkPolicySummary(t, "auth-operator/default-deny-all", operatorDefaultDeny)
	np.LogNetworkPolicyDetails(t, "auth-operator/default-deny-all", operatorDefaultDeny)
	np.RequireDefaultDenyAll(t, operatorDefaultDeny)

	operatorPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	np.LogNetworkPolicySummary(t, "auth-operator/"+authOperatorPolicyName, operatorPolicy)
	np.LogNetworkPolicyDetails(t, "auth-operator/"+authOperatorPolicyName, operatorPolicy)
	np.RequirePodSelectorLabel(t, operatorPolicy, "app", "authentication-operator")
	np.RequireIngressPort(t, operatorPolicy, corev1.ProtocolTCP, 8443)
	np.LogIngressFromNamespaceOptional(t, operatorPolicy, 8443, "openshift-monitoring")
	np.RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 5353)
	np.RequireEgressPort(t, operatorPolicy, corev1.ProtocolUDP, 5353)
	np.RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 6443)
	np.RequireEgressPort(t, operatorPolicy, corev1.ProtocolTCP, 8443)
	np.LogEgressAllowAllTCP(t, operatorPolicy)

	g.By("Verifying pods are ready in auth namespaces")
	np.WaitForPodsReadyByLabel(t, ctx, kubeClient, authNamespace, "app=oauth-openshift")
	np.WaitForPodsReadyByLabel(t, ctx, kubeClient, oauthAPINamespace, "app=openshift-oauth-apiserver")
	np.WaitForPodsReadyByLabel(t, ctx, kubeClient, authOperatorNamespace, "app=authentication-operator")
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
	expectedAuthPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName)
	expectedOAuthAPIPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName)
	expectedAuthOperatorPolicy := np.GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName)
	expectedAuthDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName)
	expectedOAuthAPIDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName)
	expectedAuthOperatorDefaultDeny := np.GetNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName)

	g.By("Deleting main policies and waiting for restoration")
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthPolicy, reconcileTimeout)
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedOAuthAPIPolicy, reconcileTimeout)
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthOperatorPolicy, reconcileTimeout)

	g.By("Deleting default-deny-all policies and waiting for restoration")
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthDefaultDeny, reconcileTimeout)
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedOAuthAPIDefaultDeny, reconcileTimeout)
	np.RestoreNetworkPolicy(t, ctx, kubeClient, expectedAuthOperatorDefaultDeny, reconcileTimeout)

	g.By("Mutating main policies and waiting for reconciliation")
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authNamespace, oauthServerPolicyName, reconcileTimeout)
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, oauthAPIServerPolicyName, reconcileTimeout)
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, authOperatorPolicyName, reconcileTimeout)

	g.By("Mutating default-deny-all policies and waiting for reconciliation")
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authNamespace, defaultDenyAllPolicyName, reconcileTimeout)
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, oauthAPINamespace, defaultDenyAllPolicyName, reconcileTimeout)
	np.MutateAndRestoreNetworkPolicy(t, ctx, kubeClient, authOperatorNamespace, defaultDenyAllPolicyName, reconcileTimeout)

	g.By("Checking NetworkPolicy-related events (best-effort)")
	np.LogNetworkPolicyEvents(t, ctx, kubeClient, []string{authOperatorNamespace, authNamespace, oauthAPINamespace}, oauthServerPolicyName)
}
