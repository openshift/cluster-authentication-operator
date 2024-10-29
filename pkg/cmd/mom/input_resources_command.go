package mom

import (
	"context"

	"github.com/openshift/multi-operator-manager/pkg/library/libraryinputresources"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
)

func NewInputResourcesCommand(streams genericiooptions.IOStreams) *cobra.Command {
	return libraryinputresources.NewInputResourcesCommand(runInputResources, streams)
}

func runInputResources(ctx context.Context) (*libraryinputresources.InputResources, error) {
	return &libraryinputresources.InputResources{
		ApplyConfigurationResources: libraryinputresources.ResourceList{
			ExactResources: []libraryinputresources.ExactResourceID{
				// Operator
				libraryinputresources.ExactLowLevelOperator("authentications"),
				libraryinputresources.ExactConfigMap("openshift-authentication-operator", "trusted-ca-bundle"),
				// config.openshift.io
				libraryinputresources.ExactConfigResource("apiservers"),
				libraryinputresources.ExactConfigResource("infrastructures"),
				libraryinputresources.ExactConfigResource("oauths"),
				libraryinputresources.ExactConfigResource("ingresses"),
				libraryinputresources.ExactConfigResource("consoles"),
				libraryinputresources.ExactConfigResource("proxies"),
				libraryinputresources.ExactResource("config.openshift.io", "v1", "clusterversions", "", "version"),
				// Core
				libraryinputresources.ExactResource("", "v1", "endpoints", "openshift-authentication", "oauth-openshift"),
				libraryinputresources.ExactResource("", "v1", "endpoints", "default", "kubernetes"),
				libraryinputresources.ExactResource("", "v1", "services", "default", "kubernetes"),
				// Configuration
				libraryinputresources.ExactConfigMap("openshift-config-managed", "oauth-openshift"),
				libraryinputresources.ExactConfigMap("openshift-config-managed", "router-certs"),
				libraryinputresources.ExactConfigMap("openshift-config-managed", "default-ingress-cert"),
				// Operand
				libraryinputresources.ExactConfigMap("openshift-authentication", "v4-0-config-system-metadata"),
				libraryinputresources.ExactConfigMap("openshift-authentication", "v4-0-config-system-service-ca"),
				libraryinputresources.ExactSecret("openshift-authentication", "v4-0-config-system-serving-cert"),
				libraryinputresources.ExactSecret("openshift-authentication", "v4-0-config-system-session"),
				libraryinputresources.ExactSecret("openshift-authentication", "v4-0-config-system-router-certs"),
				libraryinputresources.ExactSecret("openshift-authentication", "v4-0-config-system-custom-router-certs"),
				libraryinputresources.ExactSecret("openshift-authentication", "v4-0-config-system-ocp-branding-template"),
				// oauth-apiserver
				libraryinputresources.ExactClusterRole("system:openshift:useroauthaccesstoken-manager"),
				libraryinputresources.ExactClusterRoleBinding("system:openshift:useroauthaccesstoken-manager"),
				libraryinputresources.ExactClusterRoleBinding("system:openshift:oauth-apiserver"),
				libraryinputresources.ExactDeployment("openshift-oauth-apiserver", "openshift-oauth-apiserver"),
				libraryinputresources.ExactNamespace("openshift-oauth-apiserver"),
				libraryinputresources.ExactResource("policy", "v1", "poddisruptionbudgets", "openshift-oauth-apiserver", "oauth-apiserver-pdb"),
				libraryinputresources.ExactServiceAccount("openshift-oauth-apiserver", "oauth-apiserver-sa"),
				libraryinputresources.ExactResource("", "v1", "services", "openshift-oauth-apiserver", "api"),
				// oauth-openshift
				libraryinputresources.ExactConfigMap("openshift-authentication", "audit"),
				libraryinputresources.ExactClusterRoleBinding("system:openshift:openshift-authentication"),
				libraryinputresources.ExactConfigMap("openshift-authentication", "v4-0-config-system-trusted-ca-bundle"),
				libraryinputresources.ExactDeployment("openshift-authentication", "oauth-openshift"),
				libraryinputresources.ExactNamespace("openshift-authentication"),
				libraryinputresources.ExactResource("", "v1", "services", "openshift-authentication", "oauth-openshift"),
				libraryinputresources.ExactResource("route.openshift.io", "v1", "routes", "openshift-authentication", "oauth-openshift"),
				libraryinputresources.ExactServiceAccount("openshift-authentication", "oauth-openshift"),
				libraryinputresources.ExactRoleBinding("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				libraryinputresources.ExactRole("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
			},
		},
	}, nil
}
