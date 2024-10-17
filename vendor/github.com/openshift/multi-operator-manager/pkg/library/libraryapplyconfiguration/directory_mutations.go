package libraryapplyconfiguration

import (
	"errors"
	"fmt"
	"github.com/openshift/library-go/pkg/manifestclient"
	"path/filepath"
)

type directoryBasedClusterApplyResult struct {
	clusterType ClusterType

	allRequests *manifestclient.AllActionsTracker[manifestclient.FileOriginatedSerializedRequest]
}

var (
	_ SingleClusterDesiredMutationGetter = &directoryBasedClusterApplyResult{}
)

func (s *directoryBasedClusterApplyResult) GetClusterType() ClusterType {
	return s.clusterType
}

func (s *directoryBasedClusterApplyResult) Requests() MutationActionReader {
	return s.allRequests
}

// newApplyConfigurationFromDirectory takes a standard output directory, selects the subdirectory for the clusterType, and consumes the
// content inside that directory.
// All files can be either json or yaml.
func newApplyConfigurationFromDirectory(outputDirectory string) (*applyConfiguration, error) {
	ret := &applyConfiguration{
		desiredMutationsByClusterType: map[ClusterType]SingleClusterDesiredMutationGetter{},
	}

	errs := []error{}
	var err error
	for clusterType := range AllClusterTypes {
		ret.desiredMutationsByClusterType[clusterType], err = newApplyResultFromDirectory(ClusterTypeConfiguration, outputDirectory)
		if err != nil {
			errs = append(errs, fmt.Errorf("failure building %q result: %w", clusterType, err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return ret, nil
}

func newApplyResultFromDirectory(clusterType ClusterType, outputDirectory string) (*directoryBasedClusterApplyResult, error) {
	clusterTypeDir := filepath.Join(outputDirectory, string(clusterType))
	mutationRequests, err := manifestclient.ReadMutationDirectory(clusterTypeDir)
	if err != nil {
		return nil, fmt.Errorf("unable to read actions for clusterType=%q in %q: %w", clusterType, clusterTypeDir, err)
	}

	ret := &directoryBasedClusterApplyResult{
		clusterType: clusterType,
		allRequests: mutationRequests,
	}

	return ret, nil
}
