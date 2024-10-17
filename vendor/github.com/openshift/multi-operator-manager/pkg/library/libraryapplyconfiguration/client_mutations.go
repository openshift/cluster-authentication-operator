package libraryapplyconfiguration

import (
	"github.com/openshift/library-go/pkg/manifestclient"
)

type clientBasedClusterApplyResult struct {
	clusterType ClusterType

	mutationTracker *manifestclient.AllActionsTracker[manifestclient.TrackedSerializedRequest]
}

var (
	_ SingleClusterDesiredMutationGetter = &clientBasedClusterApplyResult{}
)

func (s *clientBasedClusterApplyResult) GetClusterType() ClusterType {
	return s.clusterType
}

func (s *clientBasedClusterApplyResult) Requests() MutationActionReader {
	return s.mutationTracker
}

func NewApplyConfigurationFromClient(mutationTracker *manifestclient.AllActionsTracker[manifestclient.TrackedSerializedRequest]) *applyConfiguration {
	ret := &applyConfiguration{
		desiredMutationsByClusterType: map[ClusterType]SingleClusterDesiredMutationGetter{},
	}
	for clusterType := range AllClusterTypes {
		ret.desiredMutationsByClusterType[clusterType] = &clientBasedClusterApplyResult{
			clusterType:     clusterType,
			mutationTracker: mutationTracker,
		}
	}

	return ret
}
