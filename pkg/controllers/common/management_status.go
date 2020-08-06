package common

import (
	"context"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func WithManagementStateSync(operatorClient v1helpers.OperatorClient, delegate factory.SyncFunc) factory.SyncFunc {
	return func(ctx context.Context, syncContext factory.SyncContext) error {
		spec, _, _, err := operatorClient.GetOperatorState()
		if err != nil {
			return err
		}

		if !management.IsOperatorManaged(spec.ManagementState) {
			return nil
		}

		return delegate(ctx, syncContext)
	}
}
