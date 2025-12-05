package configure

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
	"k8s.io/pod-security-admission/api"
)

type kubeObject interface {
	runtime.Object
	metav1.Object
}

var _ = g.Describe("[sig-auth][Suite:cluster-authentication-operator/externaloidc/configure][Serial][Slow][Disruptive]", func() {
	defer g.GinkgoRecover()
	var oc *exutil.CLI
	var ctx context.Context

	g.BeforeEach(func() {
		oc = exutil.NewCLIWithoutNamespace("oidc-e2e")
		oc.KubeFramework().NamespacePodSecurityLevel = api.LevelPrivileged
		oc.SetNamespace("oidc-e2e")
		ctx = context.TODO()
	})

	g.Describe("[OCPFeatureGate:ExternalOIDC] external IdP is configured", func() {
		var keycloakCLI *externaloidc.KeycloakClient

		g.BeforeEach(func() {
			kcURL, err := externaloidc.AdmittedURLForRoute(ctx, oc, externaloidc.KeycloakResourceName, externaloidc.KeycloakNamespace)
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error getting keycloak route URL")

			keycloakCli, err := externaloidc.KeycloakClientFor(kcURL)
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error creating a keycloak client")

			keycloakCLI = keycloakCli
		})

		g.It("should configure kube-apiserver", func() {
			kas, err := oc.AdminOperatorClient().OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error getting the kubeapiservers.operator.openshift.io/cluster")

			observedConfig := map[string]interface{}{}
			err = json.Unmarshal(kas.Spec.ObservedConfig.Raw, &observedConfig)
			o.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error unmarshalling the KAS observed configuration")

			o.Expect(observedConfig["authConfig"]).To(o.BeNil(), "authConfig should not be specified when OIDC authentication is configured")

			apiServerArgs := observedConfig["apiServerArguments"].(map[string]interface{})

			o.Expect(apiServerArgs["authentication-token-webhook-config-file"]).To(o.BeNil(), "authentication-token-webhook-config-file argument should not be specified when OIDC authentication is configured")
			o.Expect(apiServerArgs["authentication-token-webhook-version"]).To(o.BeNil(), "authentication-token-webhook-version argument should not be specified when OIDC authentication is configured")

			o.Expect(apiServerArgs["authentication-config"]).NotTo(o.BeNil(), "authentication-config argument should be specified when OIDC authentication is configured")
			o.Expect(apiServerArgs["authentication-config"].([]interface{})[0].(string)).To(o.Equal("/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"))
		})

		g.It("should remove the OpenShift OAuth stack", func() {
			o.Eventually(func(gomega o.Gomega) {
				_, err := oc.AdminKubeClient().AppsV1().Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
				gomega.Expect(err).NotTo(o.BeNil(), "should not be able to get the integrated oauth stack")
				gomega.Expect(apierrors.IsNotFound(err)).To(o.BeTrue(), "integrated oauth stack should not be present when OIDC authentication is configured")
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})

		/* No idea how we are going to continue to test this...
		g.It("should not accept tokens provided by the OAuth server", func() {
			o.Eventually(func(gomega o.Gomega) {
				clientset, err := kubernetes.NewForConfig(oauthUserConfig)
				gomega.Expect(err).NotTo(o.HaveOccurred())

				_, err = clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-info", username),
					},
				}, metav1.CreateOptions{})
				gomega.Expect(err).ShouldNot(o.BeNil(), "should not be able to create SelfSubjectReview using OAuth client token")
				gomega.Expect(apierrors.IsUnauthorized(err)).To(o.BeTrue(), "should receive an unauthorized error when trying to create SelfSubjectReview using OAuth client token")
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})
		*/

		g.It("should accept authentication via a certificate-based kubeconfig (break-glass)", func() {
			_, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).List(ctx, metav1.ListOptions{})
			o.Expect(err).NotTo(o.HaveOccurred(), "should be able to list pods using certificate-based authentication")
		})

		g.It("should map cluster identities correctly", func() {
			// should always be able to create an SSR for yourself
			o.Eventually(func(gomega o.Gomega) {
				err := keycloakCLI.Authenticate("admin-cli", externaloidc.Username, externaloidc.Password)
				gomega.Expect(err).NotTo(o.HaveOccurred(), "should not encounter an error authenticating as keycloak user")

				copiedOC := *oc
				token := keycloakCLI.AccessToken()
				tokenOC := copiedOC.WithToken(token)
				ssr, err := tokenOC.KubeClient().AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-info", externaloidc.Username),
					},
				}, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(o.HaveOccurred(), "should be able to create a SelfSubjectReview")

				gomega.Expect(ssr.Status.UserInfo.Username).To(o.Equal(fmt.Sprintf("%s@payload.openshift.io", externaloidc.Username)))
				gomega.Expect(ssr.Status.UserInfo.Groups).To(o.ContainElement(externaloidc.Group))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
		})

		// Note: This is included as a part of this suite instead of the uidextra suite because this suite
		// tests the behavior of a baseline configuration, which this particular test case is testing for
		// due to defaulting behavior that happens if UID claim mappings are not provided.
		// Co-locating this test case as part of this suite means we have a faster testing loop because
		// this suite already expects to have a baseline configuration rolled out before these test specs get executed.
		g.Describe("[OCPFeatureGate:ExternalOIDCWithUIDAndExtraClaimMappings] without specified UID or Extra claim mappings", g.Ordered, func() {
			g.It("should default UID to the 'sub' claim in the access token from the IdP", func() {
				// should always be able to create an SSR for yourself
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
					ssr, err := tokenOC.KubeClient().AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{
						ObjectMeta: metav1.ObjectMeta{
							Name: fmt.Sprintf("%s-info", externaloidc.Username),
						},
					}, metav1.CreateOptions{})
					gomega.Expect(err).NotTo(o.HaveOccurred(), "should be able to create a SelfSubjectReview")

					gomega.Expect(ssr.Status.UserInfo.UID).ToNot(o.BeEmpty())
				}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(o.Succeed())
			})
		})
	})
})
