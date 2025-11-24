package mom

import (
	"context"

	"github.com/openshift/multi-operator-manager/pkg/library/libraryoutputresources"
	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
)

func NewOutputResourcesCommand(streams genericiooptions.IOStreams) *cobra.Command {
	return libraryoutputresources.NewOutputResourcesCommand(runOutputResources, streams)
}

func runOutputResources(ctx context.Context) (*libraryoutputresources.OutputResources, error) {
	return &libraryoutputresources.OutputResources{
		ConfigurationResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactConfigResource("ingresses"),
			},
		},
		ManagementResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactClusterOperator("authentication"),
				libraryoutputresources.ExactLowLevelOperator("authentications"),
				libraryoutputresources.ExactNamespace("openshift-authentication"),
				libraryoutputresources.ExactNamespace("openshift-oauth-apiserver"),

				libraryoutputresources.ExactConfigMap("openshift-authentication", "audit"),
				libraryoutputresources.ExactConfigMap("openshift-authentication", "v4-0-config-system-trusted-ca-bundle"),
				libraryoutputresources.ExactDeployment("openshift-authentication", "oauth-openshift"),
				libraryoutputresources.ExactDeployment("openshift-oauth-apiserver", "apiserver"),
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-session"),
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-ocp-branding-template"),
				libraryoutputresources.ExactService("openshift-authentication", "oauth-openshift"),
				libraryoutputresources.ExactServiceAccount("openshift-authentication", "oauth-openshift"),

				libraryoutputresources.ExactRole("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				libraryoutputresources.ExactRoleBinding("openshift-config-managed", "system:openshift:oauth-servercert-trust"),

				libraryoutputresources.ExactPDB("openshift-oauth-apiserver", "oauth-apiserver-pdb"),
			},
			EventingNamespaces: []string{
				"openshift-authentication-operator",
			},
		},
		UserWorkloadResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactClusterRoleBinding("system:openshift:openshift-authentication"),
				libraryoutputresources.ExactClusterRoleBinding("system:openshift:oauth-apiserver"),
				libraryoutputresources.ExactClusterRoleBinding("system:openshift:useroauthaccesstoken-manager"),
				libraryoutputresources.ExactClusterRole("system:openshift:useroauthaccesstoken-manager"),
				libraryoutputresources.ExactOAuthClient("openshift-browser-client"),
				libraryoutputresources.ExactOAuthClient("openshift-challenging-client"),
				libraryoutputresources.ExactOAuthClient("openshift-cli-client"),

				// these are used to access resources in the user workload cluster
				libraryoutputresources.ExactServiceAccount("openshift-oauth-apiserver", "oauth-apiserver-sa"),
				libraryoutputresources.ExactService("openshift-oauth-apiserver", "api"),

				libraryoutputresources.ExactResource(apiextensionsv1.SchemeGroupVersion.Group, apiextensionsv1.SchemeGroupVersion.Version, "customresourcedefinitions", "", "rolebindingrestrictions.authorization.openshift.io"),
			},
			GeneratedNameResources: []libraryoutputresources.GeneratedResourceID{
				libraryoutputresources.GeneratedCSR("system:openshift:openshift-authenticator-"),
			},
		},
	}, nil
}
