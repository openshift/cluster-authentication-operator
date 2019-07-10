package legacyconditions

import (
	"monis.app/go/openshift/operator"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/nokey"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// NewLegacyConditions is a control loop that allows us to remove conditions that we no longer set.
// This is important as we do not want to leave an orphaned FooDegraded condition behind (ex: we remove
// a control loop or change the type of the condition to have a better name).  Otherwise we risk the
// ClusterOperatorStatusController's union logic permanently setting Degraded due to the orphaned condition.
// Note that this applies to all condition types such as Available, Progressing, etc.
func NewLegacyConditions(client v1helpers.OperatorClient, conditionTypes ...string) operator.Runner {
	return operator.New("LegacyConditions",
		nokey.SyncFunc(func() error {
			_, _, updateError := v1helpers.UpdateStatus(client, func(status *operatorv1.OperatorStatus) error {
				for _, conditionType := range conditionTypes {
					v1helpers.RemoveOperatorCondition(&status.Conditions, conditionType)
				}
				return nil
			})
			return updateError
		}),
		operator.WithInformer(client, operator.FilterByNames("cluster")),
	)
}
