package libraryapplyconfiguration

import (
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/util/sets"
	"os"
	"path/filepath"
)

type ApplyConfigurationResult interface {
	Error() error
	OutputDirectory() (string, error)
	Stdout() string
	Stderr() string

	AllDesiredMutationsGetter
}

type simpleApplyConfigurationResult struct {
	err             error
	outputDirectory string
	stdout          string
	stderr          string

	applyConfiguration *applyConfiguration
}

var (
	_ AllDesiredMutationsGetter = &simpleApplyConfigurationResult{}
	_ ApplyConfigurationResult  = &simpleApplyConfigurationResult{}
)

func NewApplyConfigurationResultFromDirectory(outputDirectory string, execError error) (ApplyConfigurationResult, error) {
	errs := []error{}
	var err error

	stdoutContent := []byte{}
	stdoutLocation := filepath.Join(outputDirectory, "stdout.log")
	stdoutContent, err = os.ReadFile(stdoutLocation)
	if err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed reading %q: %w", stdoutLocation, err))
	}
	// TODO stream through and preserve first and last to avoid memory explosion
	if len(stdoutContent) > 512*1024 {
		indexToStart := len(stdoutContent) - (512 * 1024)
		stdoutContent = stdoutContent[indexToStart:]
	}

	stderrContent := []byte{}
	stderrLocation := filepath.Join(outputDirectory, "stderr.log")
	stderrContent, err = os.ReadFile(stderrLocation)
	if err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed reading %q: %w", stderrLocation, err))
	}
	// TODO stream through and preserve first and last to avoid memory explosion
	if len(stderrContent) > 512*1024 {
		indexToStart := len(stderrContent) - (512 * 1024)
		stderrContent = stderrContent[indexToStart:]
	}

	if execError != nil {
		return &simpleApplyConfigurationResult{
			stdout:          string(stdoutContent),
			stderr:          string(stderrContent),
			err:             execError,
			outputDirectory: outputDirectory,

			applyConfiguration: &applyConfiguration{},
		}, execError
	}

	outputContent, err := os.ReadDir(outputDirectory)
	if err != nil {
		return nil, fmt.Errorf("unable to read output-dir content %q: %w", outputDirectory, err)
	}

	ret := &simpleApplyConfigurationResult{
		stdout:             string(stdoutContent),
		stderr:             string(stderrContent),
		outputDirectory:    outputDirectory,
		applyConfiguration: &applyConfiguration{},
	}
	ret.applyConfiguration, err = newApplyConfigurationFromDirectory(outputDirectory)
	if err != nil {
		errs = append(errs, fmt.Errorf("failure building applyConfiguration result: %w", err))
	}

	// check to be sure we don't have any extra content
	for _, currContent := range outputContent {
		if currContent.Name() == "stdout.log" {
			continue
		}
		if currContent.Name() == "stderr.log" {
			continue
		}

		if !currContent.IsDir() {
			errs = append(errs, fmt.Errorf("unexpected file %q, only target cluster directories are: %v", filepath.Join(outputDirectory, currContent.Name()), sets.List(AllClusterTypes)))
			continue
		}
		if !AllClusterTypes.Has(ClusterType(currContent.Name())) {
			errs = append(errs, fmt.Errorf("unexpected file %q, only target cluster directories are: %v", filepath.Join(outputDirectory, currContent.Name()), sets.List(AllClusterTypes)))
			continue
		}
	}

	ret.err = errors.Join(errs...)
	if ret.err != nil {
		// TODO may decide to disallow returning any info later
		return ret, ret.err
	}
	return ret, nil
}

func (s *simpleApplyConfigurationResult) Stdout() string {
	return s.stdout
}

func (s *simpleApplyConfigurationResult) Stderr() string {
	return s.stderr
}

func (s *simpleApplyConfigurationResult) Error() error {
	return s.err
}

func (s *simpleApplyConfigurationResult) OutputDirectory() (string, error) {
	return s.outputDirectory, nil
}

func (s *simpleApplyConfigurationResult) MutationsForClusterType(clusterType ClusterType) SingleClusterDesiredMutationGetter {
	return s.applyConfiguration.MutationsForClusterType(clusterType)
}
