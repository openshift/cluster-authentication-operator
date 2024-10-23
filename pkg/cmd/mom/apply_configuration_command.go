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
	return libraryapplyconfiguration.NewApplyConfigurationCommand(RunApplyConfiguration, RunOutputResources, streams)
}

func RunApplyConfiguration(ctx context.Context, input libraryapplyconfiguration.ApplyConfigurationInput) (libraryapplyconfiguration.AllDesiredMutationsGetter, error) {
	authenticationOperatorInput, err := operator.CreateOperatorInputFromMOM(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("unable to configure operator input: %w", err)
	}
	operatorStarter, err := operator.CreateOperatorStarter(ctx, authenticationOperatorInput)
	if err != nil {
		return nil, fmt.Errorf("unable to configure operators: %w", err)
	}
	var operatorRunError error
	if err := operatorStarter.RunOnce(ctx); err != nil {
		operatorRunError = fmt.Errorf("unable to run operators: %w", err)
	}

	return libraryapplyconfiguration.NewApplyConfigurationFromClient(input.MutationTrackingClient.GetMutations()), operatorRunError
}
