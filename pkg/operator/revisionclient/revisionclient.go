package revisionclient

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/library-go/pkg/operator/revisioncontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// OAuthAPIServerLatestRevision is an LatestRevisionClient implementation for oauth-apiserver.
type OAuthAPIServerLatestRevision struct {
	v1helpers.OperatorClient
	authOperatorClient operatorconfigclient.AuthenticationsGetter
}

var _ revisioncontroller.LatestRevisionClient = &OAuthAPIServerLatestRevision{}

func New(genericOperatorClient v1helpers.OperatorClient, authOperatorClient operatorconfigclient.AuthenticationsGetter) *OAuthAPIServerLatestRevision {
	return &OAuthAPIServerLatestRevision{OperatorClient: genericOperatorClient, authOperatorClient: authOperatorClient}
}

// GetLatestRevisionState returns the spec, status and latest revision.
func (c *OAuthAPIServerLatestRevision) GetLatestRevisionState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, int32, string, error) {
	ctx := context.TODO() // needs support in library-go
	o, err := c.authOperatorClient.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, nil, 0, "", err
	}
	return &o.Spec.OperatorSpec, &o.Status.OperatorStatus, o.Status.OAuthAPIServer.LatestAvailableRevision, o.ResourceVersion, nil
}

// UpdateLatestRevisionOperatorStatus updates the status with the given latestAvailableRevision and the by applying the given updateFuncs.
func (c *OAuthAPIServerLatestRevision) UpdateLatestRevisionOperatorStatus(latestAvailableRevision int32, updateFuncs ...v1helpers.UpdateStatusFunc) (*operatorv1.OperatorStatus, bool, error) {
	ctx := context.TODO() // needs support in library-go
	updated := false
	var updatedOperatorStatus *operatorv1.OperatorStatus
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		old, err := c.authOperatorClient.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}

		modified := old.DeepCopy()
		for _, update := range updateFuncs {
			if err := update(&modified.Status.OperatorStatus); err != nil {
				return err
			}
		}
		modified.Status.OAuthAPIServer.LatestAvailableRevision = latestAvailableRevision

		if equality.Semantic.DeepEqual(old, modified) {
			// We return the newStatus which is a deep copy of oldStatus but with all update funcs applied.
			updatedOperatorStatus = &modified.Status.OperatorStatus
			return nil
		}

		modified, err = c.authOperatorClient.Authentications().UpdateStatus(ctx, modified, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		updated = true
		updatedOperatorStatus = &modified.Status.OperatorStatus
		return nil
	})

	return updatedOperatorStatus, updated, err
}
