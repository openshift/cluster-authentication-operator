package mom

import (
	"context"

	"github.com/openshift/multi-operator-manager/pkg/library/libraryoutputresources"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
)

func NewOutputResourcesCommand(streams genericiooptions.IOStreams) *cobra.Command {
	return libraryoutputresources.NewOutputResourcesCommand(RunOutputResources, streams)
}

func RunOutputResources(ctx context.Context) (*libraryoutputresources.OutputResources, error) {
	return &libraryoutputresources.OutputResources{
		ConfigurationResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactResource("config.openshift.io", "ingresses", "", "cluster"),
			},
		},
		ManagementResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactClusterOperator("authentication"),
				libraryoutputresources.ExactResource("operator.openshift.io", "authentications", "", "cluster"),
			},
		},
		UserWorkloadResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-session"),
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-ocp-branding-template"),
				libraryoutputresources.ExactServiceAccount("openshift-authentication", "oauth-openshift"),
				libraryoutputresources.ExactDeployments("openshift-authentication", "oauth-openshift"),
				exactOAuthClient("openshift-browser-client"),
				exactOAuthClient("openshift-challenging-client"),
				exactOAuthClient("openshift-cli-client"),
				libraryoutputresources.ExactClusterRoleBinding("system:openshift:openshift-authentication"),
				libraryoutputresources.ExactRoleBinding("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				libraryoutputresources.ExactRole("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
			},
			GeneratedNameResources: []libraryoutputresources.GeneratedResourceID{
				libraryoutputresources.GeneratedCSR("system:openshift:openshift-authenticator-"),
			},
		},
	}, nil
}

func exactOAuthClient(name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResource("oauth.openshift.io", "oauthclients", "", name)
}
