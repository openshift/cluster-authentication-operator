package libraryapplyconfiguration

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/openshift/library-go/pkg/manifestclient"
	"k8s.io/apimachinery/pkg/util/sets"
)

// MutationActionReader provides access to serialized mutation requests
type MutationActionReader interface {
	ListActions() []manifestclient.Action
	RequestsForAction(action manifestclient.Action) []manifestclient.SerializedRequestish
	AllRequests() []manifestclient.SerializedRequestish
}

// SingleClusterDesiredMutationGetter provides access to mutations targeted at a single type of cluster
type SingleClusterDesiredMutationGetter interface {
	GetClusterType() ClusterType
	Requests() MutationActionReader
}

// AllDesiredMutationsGetter provides access to mutations targeted at all available types of clusters
type AllDesiredMutationsGetter interface {
	MutationsForClusterType(clusterType ClusterType) SingleClusterDesiredMutationGetter
}

type applyConfiguration struct {
	desiredMutationsByClusterType map[ClusterType]SingleClusterDesiredMutationGetter
}

var (
	_ AllDesiredMutationsGetter = &applyConfiguration{}
)

func ValidateAllDesiredMutationsGetter(s AllDesiredMutationsGetter) error {
	errs := []error{}

	if s == nil {
		return fmt.Errorf("applyConfiguration is required")
	}

	for _, clusterType := range sets.List(AllClusterTypes) {
		desiredMutationsGetter := s.MutationsForClusterType(clusterType)
		switch {
		case desiredMutationsGetter == nil:
			errs = append(errs, fmt.Errorf("mutations for %q are required even if empty", clusterType))
		case desiredMutationsGetter.GetClusterType() != clusterType:
			errs = append(errs, fmt.Errorf("mutations for %q reported type=%q", clusterType, desiredMutationsGetter.GetClusterType()))
		}
	}

	return errors.Join(errs...)
}

func WriteApplyConfiguration(desiredApplyConfiguration AllDesiredMutationsGetter, outputDirectory string) error {
	errs := []error{}

	for _, clusterType := range sets.List(AllClusterTypes) {
		desiredMutations := desiredApplyConfiguration.MutationsForClusterType(clusterType)
		err := manifestclient.WriteMutationDirectory(filepath.Join(outputDirectory, string(clusterType)), desiredMutations.Requests().AllRequests()...)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed writing requests for %q: %w", clusterType, err))
		}
	}

	return errors.Join(errs...)
}

func (s *applyConfiguration) MutationsForClusterType(clusterType ClusterType) SingleClusterDesiredMutationGetter {
	return s.desiredMutationsByClusterType[clusterType]
}

type ClusterType string

var (
	ClusterTypeConfiguration ClusterType = "Configuration"
	ClusterTypeManagement    ClusterType = "Management"
	ClusterTypeUserWorkload  ClusterType = "UserWorkload"
	AllClusterTypes                      = sets.New(ClusterTypeConfiguration, ClusterTypeManagement, ClusterTypeUserWorkload)
)
