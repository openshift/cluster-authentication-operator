package main

import (
	"os"

	"github.com/spf13/cobra"

	"k8s.io/component-base/cli"

	"github.com/openshift/cluster-authentication-operator/pkg/cmd/operator"
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

	cmd.AddCommand(operator.NewOperator())

	return cmd
}
