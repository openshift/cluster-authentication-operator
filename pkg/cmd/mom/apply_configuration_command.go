package mom

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-authentication-operator/pkg/operator"
	"github.com/openshift/multi-operator-manager/pkg/library/libraryapplyconfiguration"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
)

func NewApplyConfigurationCommand(streams genericiooptions.IOStreams) *cobra.Command {
	return libraryapplyconfiguration.NewApplyConfigurationCommand(RunApplyConfiguration, runOutputResources, streams)
}

func RunApplyConfiguration(ctx context.Context, input libraryapplyconfiguration.ApplyConfigurationInput) (*libraryapplyconfiguration.ApplyConfigurationRunResult, libraryapplyconfiguration.AllDesiredMutationsGetter, error) {
	authenticationOperatorInput, err := operator.CreateOperatorInputFromMOM(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to configure operator input: %w", err)
	}
	operatorStarter, err := operator.CreateOperatorStarter(ctx, authenticationOperatorInput)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to configure operators: %w", err)
	}
	return operatorStarter.RunOnce(ctx, input)
}
