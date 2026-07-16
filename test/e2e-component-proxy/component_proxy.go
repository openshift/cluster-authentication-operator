package component_proxy

import (
	"context"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Serial][Operator][ComponentProxy] should set Degraded when spec.proxy points to an unreachable proxy", func() {
		testDegradedOnBadProxyURL()
	})
})

func testDegradedOnBadProxyURL() {
	ctx := context.Background()
	t := g.GinkgoTB()

	g.By("Creating test clients")
	clients := test.NewTestClients(t)

	checkFeatureGateOrSkip(ctx, clients)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Saving original proxy config for cleanup")
	operatorAuth, err := clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	originalProxy := operatorAuth.Spec.Proxy.DeepCopy()

	g.DeferCleanup(func() {
		g.GinkgoWriter.Println("cleaning up: restoring original proxy config")
		fresh, err := clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			g.GinkgoWriter.Printf("cleanup: failed to get operator auth: %v\n", err)
			return
		}
		if originalProxy != nil {
			fresh.Spec.Proxy = *originalProxy
		} else {
			fresh.Spec.Proxy = operatorv1.AuthenticationProxyConfig{}
		}
		if _, err := clients.OperatorClient.OperatorV1().Authentications().Update(ctx, fresh, metav1.UpdateOptions{}); err != nil {
			g.GinkgoWriter.Printf("cleanup: failed to restore proxy: %v\n", err)
			return
		}

		g.GinkgoWriter.Println("cleanup: waiting for ProxyConfigControllerDegraded to clear")
		if err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
			config, err := clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			cond := v1helpers.FindOperatorCondition(config.Status.Conditions, "ProxyConfigControllerDegraded")
			return cond == nil || cond.Status != operatorv1.ConditionTrue, nil
		}); err != nil {
			g.GinkgoWriter.Printf("cleanup: ProxyConfigControllerDegraded did not clear: %v\n", err)
		}

		g.GinkgoWriter.Println("cleanup: waiting for operator to stabilize")
		if err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication"); err != nil {
			g.GinkgoWriter.Printf("cleanup: operator did not recover: %v\n", err)
		}
	})

	g.By("Setting spec.proxy.httpsProxy to an unreachable host")
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: "http://does-not-exist.invalid:3128",
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for ProxyConfigControllerDegraded=True on the operator CR")
	var lastCondition *operatorv1.OperatorCondition
	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		config, err := clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			g.GinkgoWriter.Printf("failed to get operator auth: %v\n", err)
			return false, nil
		}
		lastCondition = v1helpers.FindOperatorCondition(config.Status.Conditions, "ProxyConfigControllerDegraded")
		return lastCondition != nil && lastCondition.Status == operatorv1.ConditionTrue, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "ProxyConfigControllerDegraded never became True")
	o.Expect(lastCondition).NotTo(o.BeNil())
	g.GinkgoWriter.Printf("ProxyConfigControllerDegraded: status=%s reason=%s message=%s\n", lastCondition.Status, lastCondition.Reason, lastCondition.Message)

	g.By("Verifying ClusterOperator authentication is Degraded")
	err = test.WaitForClusterOperatorDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())
}

func checkFeatureGateOrSkip(ctx context.Context, clients *test.TestClients) {
	featureGates, err := clients.ConfigClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	if len(featureGates.Status.FeatureGates) != 1 {
		g.Fail("multiple feature gate versions detected")
	}

	for _, gate := range featureGates.Status.FeatureGates[0].Enabled {
		if gate.Name == features.FeatureGateAuthenticationComponentProxy {
			return
		}
	}

	g.Skip("feature gate " + string(features.FeatureGateAuthenticationComponentProxy) + " is not enabled")
}
