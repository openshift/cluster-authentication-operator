package revert

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc"
	exutil "github.com/openshift/origin/test/extended/util"
	authnv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/pod-security-admission/api"
)

type kubeObject interface {
	runtime.Object
	metav1.Object
}

var _ = g.Describe("[sig-auth][Suite:cluster-authentication-operator/externaloidc/revert][Serial][Slow][Disruptive]", func() {
	defer g.GinkgoRecover()
	var oc *exutil.CLI
	var ctx context.Context

	g.BeforeEach(func() {
		oc = exutil.NewCLIWithoutNamespace("oidc-e2e")
		oc.KubeFramework().NamespacePodSecurityLevel = api.LevelPrivileged
		oc.SetNamespace("oidc-e2e")
		ctx = context.TODO()
	})

	g.Describe("[OCPFeatureGate:ExternalOIDC] reverting to IntegratedOAuth", func() {
		g.It("should rollout configuration on the kube-apiserver successfully", func() {
			kas, err := oc.AdminOperatorClient().OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error getting the kubeapiservers.operator.openshift.io/cluster")

			observedConfig := map[string]interface{}{}
			err = json.Unmarshal(kas.Spec.ObservedConfig.Raw, &observedConfig)
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error unmarshalling the KAS observed configuration")

			o.Expect(observedConfig["authConfig"]).ToNot(o.BeNil(), "authConfig should be specified when OIDC authentication is configured")

			apiServerArgs := observedConfig["apiServerArguments"].(map[string]interface{})

			o.Expect(apiServerArgs["authentication-token-webhook-config-file"]).NotTo(o.BeNil(), "authentication-token-webhook-config-file argument should be specified when OIDC authentication is not configured")
			o.Expect(apiServerArgs["authentication-token-webhook-version"]).NotTo(o.BeNil(), "authentication-token-webhook-version argument should be specified when OIDC authentication is not configured")

			o.Expect(apiServerArgs["authentication-config"]).To(o.BeNil(), "authentication-config argument should not be specified when OIDC authentication is not configured")
		})

		g.It("should rollout the OpenShift OAuth stack", func() {
			o.Eventually(func(gomega o.Gomega) {
				_, err := oc.AdminKubeClient().AppsV1().Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
				gomega.Expect(err).Should(o.BeNil(), "should be able to get the integrated oauth stack")
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})

		g.It("should not accept tokens provided by an external IdP", func() {
			o.Eventually(func(gomega o.Gomega) {
				kcURL, err := externaloidc.AdmittedURLForRoute(ctx, oc, externaloidc.KeycloakResourceName, externaloidc.KeycloakNamespace)
				o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error getting keycloak route URL")

				keycloakCli, err := externaloidc.KeycloakClientFor(kcURL)
				o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error creating a keycloak client")

				// First authenticate as the admin keycloak user so we can add new groups and users
				err = keycloakCli.Authenticate("admin-cli", externaloidc.Username, externaloidc.Password)
				gomega.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error authenticating as keycloak user")

				copiedOC := *oc
				tokenOC := copiedOC.WithToken(keycloakCli.AccessToken())

				_, err = tokenOC.KubeClient().AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-info", externaloidc.Username),
					},
				}, metav1.CreateOptions{})
				gomega.Expect(err).To(o.HaveOccurred(), "should not be able to create a SelfSubjectReview")
				gomega.Expect(apierrors.IsUnauthorized(err)).To(o.BeTrue(), "external IdP token should be unauthorized")
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})

		g.It("should accept tokens provided by the OpenShift OAuth server", func() {
			o.Eventually(func(gomega o.Gomega) {
				oauthUserConfig := oc.GetClientConfigForUser("oidc-e2e-oauth-user")
				clientset, err := kubernetes.NewForConfig(oauthUserConfig)
				gomega.Expect(err).NotTo(o.HaveOccurred())

				_, err = clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-info", externaloidc.Username),
					},
				}, metav1.CreateOptions{})
				gomega.Expect(err).ShouldNot(o.HaveOccurred(), "should be able to create SelfSubjectReview using OAuth client token")
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})
	})
})
