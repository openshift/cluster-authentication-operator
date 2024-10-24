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
				exactResource("config.openshift.io", "ingresses", "", "cluster"),
			},
		},
		ManagementResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				exactResource("config.openshift.io", "clusteroperators", "", "authentication"),
				exactResource("openshift.openshift.io", "authentications", "", "cluster"),
			},
		},
		UserWorkloadResources: libraryoutputresources.ResourceList{
			ExactResources: []libraryoutputresources.ExactResourceID{
				exactResource("", "secrets", "openshift-authentication", "v4-0-config-system-session"),
				exactResource("", "secrets", "openshift-authentication", "v4-0-config-system-ocp-branding-template"),
				exactResource("", "serviceaccounts", "openshift-authentication", "oauth-openshift"),
				exactResource("apps", "deployments", "openshift-authentication", "oauth-openshift"),
				exactResource("oauth.openshift.io", "oauthclients", "", "openshift-browser-client"),
				exactResource("oauth.openshift.io", "oauthclients", "", "openshift-challenging-client"),
				exactResource("oauth.openshift.io", "oauthclients", "", "openshift-cli-client"),
				exactResource("rbac.authorization.k8s.io", "clusterrolebindings", "", "system:openshift:openshift-authentication"),
				exactResource("rbac.authorization.k8s.io", "rolebindings", "openshift-config-managed", "system:openshift:oauth-servercert-trust"),
				exactResource("rbac.authorization.k8s.io", "roles", "openshift-config-managed", "system:openshift:oauth-servercert-trust"),
			},
			GeneratedNameResources: []libraryoutputresources.GeneratedResourceID{
				generatedResource("certificates.k8s.io", "certificatesigningrequests", "", "system:openshift:openshift-authenticator-"),
			},
		},
	}, nil
}

func exactResource(group, resource, namespace, name string) libraryoutputresources.ExactResourceID {
	return libraryoutputresources.ExactResourceID{
		OutputResourceTypeIdentifier: libraryoutputresources.OutputResourceTypeIdentifier{
			Group:    group,
			Resource: resource,
		},
		Namespace: namespace,
		Name:      name,
	}
}

func generatedResource(group, resource, namespace, name string) libraryoutputresources.GeneratedResourceID {
	return libraryoutputresources.GeneratedResourceID{
		OutputResourceTypeIdentifier: libraryoutputresources.OutputResourceTypeIdentifier{
			Group:    group,
			Resource: resource,
		},
		Namespace:     namespace,
		GeneratedName: name,
	}
}
