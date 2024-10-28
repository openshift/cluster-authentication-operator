package libraryapplyconfiguration

import (
	"bytes"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/manifestclient"
	"k8s.io/apimachinery/pkg/util/sets"
)

func EquivalentApplyConfigurationResultIgnoringEvents(lhs, rhs ApplyConfigurationResult) []string {
	reasons := []string{}
	reasons = append(reasons, equivalentErrors("Error", lhs.Error(), rhs.Error())...)

	for _, clusterType := range sets.List(AllClusterTypes) {
		currLHS := lhs.MutationsForClusterType(clusterType)
		currRHS := rhs.MutationsForClusterType(clusterType)
		reasons = append(reasons, EquivalentClusterApplyResultIgnoringEvents(string(clusterType), currLHS, currRHS)...)
	}

	return reasons
}

func equivalentErrors(field string, lhs, rhs error) []string {
	reasons := []string{}
	switch {
	case lhs == nil && rhs == nil:
	case lhs == nil && rhs != nil:
		reasons = append(reasons, fmt.Sprintf("%v: lhs=nil, rhs=%v", field, rhs))
	case lhs != nil && rhs == nil:
		reasons = append(reasons, fmt.Sprintf("%v: lhs=%v, rhs=nil", field, lhs))
	case lhs.Error() != rhs.Error():
		reasons = append(reasons, fmt.Sprintf("%v: lhs=%v, rhs=%v", field, lhs, rhs))
	}

	return reasons
}

func EquivalentClusterApplyResultIgnoringEvents(field string, lhs, rhs SingleClusterDesiredMutationGetter) []string {
	switch {
	case lhs == nil && rhs == nil:
		return nil
	case lhs == nil && rhs != nil:
		return []string{fmt.Sprintf("%v: lhs=nil, len(rhs)=%v", field, len(rhs.Requests().AllRequests()))}
	case lhs != nil && rhs == nil:
		return []string{fmt.Sprintf("%v: len(lhs)=%v, rhs=nil", field, len(lhs.Requests().AllRequests()))}
	case lhs != nil && rhs != nil:
		// check the rest
	}

	lhsAllRequests := RemoveEvents(lhs.Requests().AllRequests())
	rhsAllRequests := RemoveEvents(rhs.Requests().AllRequests())

	// TODO different method with prettier message
	equivalent, missingInRHS, missingInLHS := manifestclient.AreAllSerializedRequestsEquivalentWithReasons(lhsAllRequests, rhsAllRequests)
	if equivalent {
		return nil
	}

	reasons := []string{}
	reasons = append(reasons, reasonForDiff("rhs", missingInRHS, lhsAllRequests, rhsAllRequests)...)

	uniquelyMissingInLHS := []manifestclient.SerializedRequest{}
	for _, currMissingInLHS := range missingInLHS {
		lhsMetadata := currMissingInLHS.GetLookupMetadata()
		found := false
		for _, currMissingInRHS := range missingInRHS {
			rhsMetadata := currMissingInRHS.GetLookupMetadata()
			if lhsMetadata == rhsMetadata {
				found = true
				break
			}
		}
		if !found {
			uniquelyMissingInLHS = append(uniquelyMissingInLHS, currMissingInLHS)
		}
	}
	reasons = append(reasons, reasonForDiff("lhs", uniquelyMissingInLHS, rhsAllRequests, lhsAllRequests)...)

	qualifiedReasons := []string{}
	for _, curr := range reasons {
		qualifiedReasons = append(qualifiedReasons, fmt.Sprintf("%s: %s", field, curr))
	}
	return qualifiedReasons
}

func reasonForDiff(nameOfDestination string, missingInDestination []manifestclient.SerializedRequest, allSourceRequests, allDestinationRequests []manifestclient.SerializedRequestish) []string {
	reasons := []string{}

	for _, currMissingInDestination := range missingInDestination {
		currSourceRequests := manifestclient.RequestsForResource(allSourceRequests, currMissingInDestination.GetLookupMetadata())
		currDestinationRequests := manifestclient.RequestsForResource(allDestinationRequests, currMissingInDestination.GetLookupMetadata())

		if len(currDestinationRequests) == 0 {
			reasons = append(reasons, fmt.Sprintf("%s is missing: %v", nameOfDestination, currMissingInDestination.StringID()))
			continue
		}

		for _, currLHS := range currSourceRequests {
			found := false
			mismatchReasons := []string{}
			for i, currRHS := range currDestinationRequests {
				if manifestclient.EquivalentSerializedRequests(currLHS, currRHS) {
					found = true
					mismatchReasons = nil
					break
				}
				// we know the metadata is the same, something else doesn't match
				if !bytes.Equal(currLHS.GetSerializedRequest().Body, currRHS.GetSerializedRequest().Body) {
					mismatchReasons = append(mismatchReasons,
						fmt.Sprintf("mutation: %v, rhs[%d]: body diff: %v",
							currMissingInDestination.StringID(),
							i,
							cmp.Diff(currLHS.GetSerializedRequest().Body, currRHS.GetSerializedRequest().Body),
						),
					)
				}
				if !bytes.Equal(currLHS.GetSerializedRequest().Options, currRHS.GetSerializedRequest().Options) {
					mismatchReasons = append(mismatchReasons,
						fmt.Sprintf("mutation: %v, rhs[%d]: options diff: %v",
							currMissingInDestination.StringID(),
							i,
							cmp.Diff(currLHS.GetSerializedRequest().Options, currRHS.GetSerializedRequest().Options),
						),
					)
				}
			}
			if found {
				continue
			}
			reasons = append(reasons, mismatchReasons...)
		}
	}
	return reasons
}
