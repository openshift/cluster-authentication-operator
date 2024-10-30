package main

import (
	"os"

	"github.com/openshift/cluster-authentication-operator/pkg/cmd/mom"
	"github.com/openshift/cluster-authentication-operator/pkg/cmd/operator"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/component-base/cli"
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

	return cmd
}
