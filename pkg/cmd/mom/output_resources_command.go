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
				libraryoutputresources.ExactConfigMap("openshift-authentication", "audit"),
				libraryoutputresources.ExactConfigMap("openshift-authentication", "v4-0-config-system-trusted-ca-bundle"),
				libraryoutputresources.ExactDeployment("openshift-authentication", "oauth-openshift"),
				libraryoutputresources.ExactLowLevelOperator("authentications"),
				exactNamespace("openshift-authentication"),
				exactRole("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				exactRoleBinding("openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-session"),
				libraryoutputresources.ExactSecret("openshift-authentication", "v4-0-config-system-ocp-branding-template"),
				exactService("openshift-authentication", "oauth-openshift"),
				libraryoutputresources.ExactServiceAccount("openshift-authentication", "oauth-openshift"),
			},
			EventingNamespaces: []string{
				"openshift-authentication-operator",
			},
		},
		UserWorkloadResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				libraryoutputresources.ExactClusterRoleBinding("system:openshift:openshift-authentication"),
				exactOAuthClient("openshift-browser-client"),
				exactOAuthClient("openshift-challenging-client"),
				exactOAuthClient("openshift-cli-client"),
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

func exactNamespace(name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResource("", "namespaces", "", name)
}

func exactService(namespace, name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResource("", "services", namespace, name)
}

func exactRole(namespace, name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResource("rbac.authorization.k8s.io", "roles", namespace, name)
}

func exactRoleBinding(namespace, name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResource("rbac.authorization.k8s.io", "rolebindings", namespace, name)
}
