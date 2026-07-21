package main

import (
	"context"
	"os"

	"github.com/openshift/cluster-authentication-operator/pkg/cmd/mom"
	"github.com/openshift/cluster-authentication-operator/pkg/cmd/operator"
	"github.com/openshift/cluster-authentication-operator/pkg/cmd/render"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/component-base/cli"

	kmshealth "github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	kmspreflight "github.com/openshift/library-go/pkg/operator/encryption/kms/preflight"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/encryptionstatusprovider"
)

func main() {
	os.Exit(cli.Run(NewAuthenticationOperatorCommand()))
}

func NewAuthenticationOperatorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authentication-operator",
		Short: "OpenShift authentication OAuth server operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}

	ioStreams := genericiooptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}

	cmd.AddCommand(operator.NewOperator())
	cmd.AddCommand(mom.NewApplyConfigurationCommand(ioStreams))
	cmd.AddCommand(mom.NewInputResourcesCommand(ioStreams))
	cmd.AddCommand(mom.NewOutputResourcesCommand(ioStreams))
	cmd.AddCommand(render.NewRender())
	cmd.AddCommand(kmshealth.NewCommand(context.Background(), encryptionstatusprovider.NewAuthenticationEncryptionStatusProviderFromConfig))
	cmd.AddCommand(kmspreflight.NewCommand(context.Background()))

	return cmd
}
