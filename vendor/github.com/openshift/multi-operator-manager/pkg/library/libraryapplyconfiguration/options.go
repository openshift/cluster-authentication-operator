package libraryapplyconfiguration

import (
	"context"
	"errors"
	"fmt"
	"os"
)

type applyConfigurationOptions struct {
	ApplyConfigurationFn ApplyConfigurationFunc

	Input ApplyConfigurationInput

	OutputDirectory string
}

func newApplyConfigurationOptions(
	applyConfigurationFn ApplyConfigurationFunc,
	input ApplyConfigurationInput,
	outputDirectory string) *applyConfigurationOptions {
	return &applyConfigurationOptions{
		ApplyConfigurationFn: applyConfigurationFn,
		Input:                input,
		OutputDirectory:      outputDirectory,
	}
}

func (o *applyConfigurationOptions) Run(ctx context.Context) error {
	if err := os.MkdirAll(o.OutputDirectory, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("unable to create output directory %q:%v", o.OutputDirectory, err)
	}

	errs := []error{}
	result, err := o.ApplyConfigurationFn(ctx, o.Input)
	if err != nil {
		errs = append(errs, err)
	}
	if err := ValidateAllDesiredMutationsGetter(result); err != nil {
		errs = append(errs, err)
	}

	if err := WriteApplyConfiguration(result, o.OutputDirectory); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
