package component_proxy

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	test "github.com/openshift/cluster-authentication-operator/test/library"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Serial][Operator][ComponentProxy] should set Degraded when spec.proxy points to an unreachable proxy", func() {
		testDegradedOnBadProxyURL()
	})
	g.It("[Serial][Operator][ComponentProxy] should emit IdPEndpointUnreachable warning when IdP is unreachable through proxy", func() {
		testWarningOnUnreachableIdP()
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

		g.GinkgoWriter.Println("cleanup: waiting for operator to pick up changes and stabilize")
		if err := test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication"); err != nil {
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

func testWarningOnUnreachableIdP() {
	ctx := context.Background()
	t := g.GinkgoTB()

	g.By("Creating test clients")
	clients := test.NewTestClients(t)

	checkFeatureGateOrSkip(ctx, clients)

	g.By("Waiting for authentication operator to be stable before test")
	err := test.WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, clients.ConfigClient.ConfigV1(), "authentication")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deploying Squid forward proxy")
	proxyURL, _, proxyCleanup := test.DeploySquidProxy(t, clients.KubeClient)
	g.DeferCleanup(func() {
		g.GinkgoWriter.Println("cleaning up: removing Squid proxy")
		proxyCleanup()
	})
	g.GinkgoWriter.Printf("Squid proxy URL: %s\n", proxyURL)

	g.By("Saving original proxy config for cleanup")
	operatorAuth, err := clients.OperatorClient.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	originalProxy := operatorAuth.Spec.Proxy.DeepCopy()

	const (
		fakeIDPName       = "e2e-unreachable-idp"
		fakeIDPSecretName = "e2e-unreachable-idp-secret"
	)

	g.DeferCleanup(func() {
		g.GinkgoWriter.Println("cleaning up: removing fake IdP from OAuth config")
		test.CleanIDPConfigByName(t, clients.ConfigClient.ConfigV1().OAuths(), fakeIDPName)

		g.GinkgoWriter.Println("cleaning up: deleting fake IdP secret")
		_ = clients.KubeClient.CoreV1().Secrets("openshift-config").Delete(ctx, fakeIDPSecretName, metav1.DeleteOptions{})

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

		g.GinkgoWriter.Println("cleanup: waiting for operator to pick up changes and stabilize")
		if err := test.WaitForOperatorToPickUpChanges(t, clients.ConfigClient.ConfigV1(), "authentication"); err != nil {
			g.GinkgoWriter.Printf("cleanup: operator did not recover: %v\n", err)
		}
	})

	g.By("Creating fake IdP client secret in openshift-config")
	_, err = clients.KubeClient.CoreV1().Secrets("openshift-config").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fakeIDPSecretName,
			Labels: test.CAOE2ETestLabels(),
		},
		Data: map[string][]byte{
			"clientSecret": []byte("fake-secret"),
		},
	}, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Adding fake OpenID IdP to OAuth config")
	oauthConfig, err := clients.ConfigClient.ConfigV1().OAuths().Get(ctx, "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	oauthCopy := oauthConfig.DeepCopy()
	oauthCopy.Spec.IdentityProviders = append(oauthCopy.Spec.IdentityProviders, configv1.IdentityProvider{
		Name:          fakeIDPName,
		MappingMethod: configv1.MappingMethodClaim,
		IdentityProviderConfig: configv1.IdentityProviderConfig{
			Type: configv1.IdentityProviderTypeOpenID,
			OpenID: &configv1.OpenIDIdentityProvider{
				ClientID: "fake-client",
				ClientSecret: configv1.SecretNameReference{
					Name: fakeIDPSecretName,
				},
				Issuer: "https://unreachable-idp.invalid",
				Claims: configv1.OpenIDClaims{
					PreferredUsername: []string{"preferred_username"},
				},
			},
		},
	})
	_, err = clients.ConfigClient.ConfigV1().OAuths().Update(ctx, oauthCopy, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Setting component-scoped proxy pointing to the Squid instance")
	startTime := time.Now()
	operatorAuth.Spec.Proxy = operatorv1.AuthenticationProxyConfig{
		HTTPSProxy: proxyURL,
	}
	_, err = clients.OperatorClient.OperatorV1().Authentications().Update(ctx, operatorAuth, metav1.UpdateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for IdPEndpointUnreachable warning event")
	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		events, err := clients.KubeClient.CoreV1().Events("openshift-authentication-operator").List(ctx, metav1.ListOptions{
			FieldSelector: "reason=IdPEndpointUnreachable",
		})
		if err != nil {
			g.GinkgoWriter.Printf("failed to list events: %v\n", err)
			return false, nil
		}
		for _, event := range events.Items {
			eventTime := event.LastTimestamp.Time
			if eventTime.IsZero() {
				eventTime = event.EventTime.Time
			}
			if event.Type == "Warning" && eventTime.After(startTime) {
				g.GinkgoWriter.Printf("found IdPEndpointUnreachable event: %s\n", event.Message)
				return true, nil
			}
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "IdPEndpointUnreachable warning event was not emitted")

	g.By("Verifying operator is NOT Degraded")
	ok, conditions, checkErr := test.CheckClusterOperatorStatus(t, ctx, clients.ConfigClient.ConfigV1(), "authentication",
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
	)
	o.Expect(checkErr).NotTo(o.HaveOccurred())
	o.Expect(ok).To(o.BeTrue(), fmt.Sprintf("operator should NOT be degraded, conditions: %v", conditions))
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
