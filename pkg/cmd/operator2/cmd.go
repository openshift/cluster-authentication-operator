package operator2

import (
	"github.com/spf13/cobra"

	"github.com/openshift/cluster-osin-operator/pkg/operator2"
	"github.com/openshift/cluster-osin-operator/pkg/version"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
)

const (
	componentName      = "cluster-osin-operator"
	componentNamespace = "openshift-core-operators"
)

func NewOperator() *cobra.Command {
	cmd := controllercmd.NewControllerCommandConfig(componentName, version.Get(), operator2.RunOperator).NewCommand()
	cmd.Use = "operator2"
	cmd.Short = "Start the Osin Operator2" // temp names and such
	return cmd
}
