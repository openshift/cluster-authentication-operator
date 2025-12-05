package uidextra

import (
	"context"
	"fmt"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-authentication-operator/tests-extension/pkg/suites/externaloidc"
	exutil "github.com/openshift/origin/test/extended/util"
	authnv1 "k8s.io/api/authentication/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/pod-security-admission/api"
)

type kubeObject interface {
	runtime.Object
	metav1.Object
}

var _ = g.Describe("[sig-auth][Suite:cluster-authentication-operator/externaloidc/uidextra][Serial][Slow][Disruptive]", func() {
	defer g.GinkgoRecover()
	var oc *exutil.CLI
	var ctx context.Context

	g.BeforeEach(func() {
		oc = exutil.NewCLIWithoutNamespace("oidc-e2e")
		oc.KubeFramework().NamespacePodSecurityLevel = api.LevelPrivileged
		oc.SetNamespace("oidc-e2e")
		ctx = context.TODO()
	})

	g.Describe("[OCPFeatureGate:ExternalOIDCWithUIDAndExtraClaimMappings] external IdP is configured", func() {
		g.Describe("with valid specified UID or Extra claim mappings", func() {
			g.Describe("checking cluster identity mapping", func() {
				ssr := &authnv1.SelfSubjectReview{}
				g.It("should map UID correctly", func() {
					o.Expect(ssr.UID).NotTo(o.Equal(strings.ToUpper(externaloidc.Username)))
				})

				g.It("should map Extra correctly", func() {
					o.Expect(ssr.Status.UserInfo.Extra).To(o.HaveKey("payload/test"))
					o.Expect(ssr.Status.UserInfo.Extra["payload/test"]).To(o.HaveLen(1))
					o.Expect(ssr.Status.UserInfo.Extra["payload/test"][0]).To(o.Equal(fmt.Sprintf("%s@payload.openshift.ioextra", externaloidc.Username)))
				})
			})
		})

		g.Describe("with invalid specified UID or Extra claim mappings", func() {
			g.It("should reject admission when UID claim expression is not compilable CEL", func() {
				_, _, err := externaloidc.ConfigureOIDCAuthentication(ctx, oc, externaloidc.KeycloakNamespace, externaloidc.OIDCClientSecret, func(o *configv1.OIDCProvider) {
					o.ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
						Expression: "!@&*#^",
					}
				})
				o.Expect(err).To(o.HaveOccurred(), "should encounter an error configuring OIDC authentication")
			})

			g.It("should reject admission when Extra claim expression is not compilable CEL", func() {
				_, _, err := externaloidc.ConfigureOIDCAuthentication(ctx, oc, externaloidc.KeycloakNamespace, externaloidc.OIDCClientSecret, func(o *configv1.OIDCProvider) {
					o.ClaimMappings.Extra = []configv1.ExtraMapping{
						{
							Key:             "payload/test",
							ValueExpression: "!@*&#^!@(*&^",
						},
					}
				})
				o.Expect(err).To(o.HaveOccurred(), "should encounter an error configuring OIDC authentication")
			})
		})
	})
})
