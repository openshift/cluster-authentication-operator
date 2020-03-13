package apiservices

import (
	"context"
	"fmt"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorclientinformers "github.com/openshift/client-go/operator/informers/externalversions"
)

// NewManageAPIServicesController sets ManagingOAuthAPIServer flag to true.
// This will make OpenShift APIServer to step down and traffic will be routed to the OAuth APIServer
//
// see https://github.com/openshift/enhancements/blob/master/enhancements/authentication/separate-oauth-resources.md
func NewManageAPIServicesController(
	name string,
	authOperatorClient operatorconfigclient.AuthenticationsGetter,
	authOperatorInformers operatorclientinformers.SharedInformerFactory,
	eventRecorder events.Recorder) factory.Controller {

	controllerFactory := factory.New()
	authOperatorLister := authOperatorInformers.Operator().V1().Authentications().Lister()

	controllerFactory.WithSync(func(ctx context.Context, controllerContext factory.SyncContext) error {
		// TODO: on already encrypted cluster we need to wait until oauth-apiserver observers the encryption config before routing traffic to it
		// otherwise we won't be able to decrypt data (OAuth tokens)
		operator, err := authOperatorLister.Get("cluster")
		if err != nil {
			return err
		}
		if !v1helpers.IsOperatorConditionTrue(operator.Status.Conditions, "Available") {
			message := "authentication operator is not Available"
			controllerContext.Recorder().Warning("PrereqNotReady", message)
			return fmt.Errorf(message)
		}

		if !operator.Status.ManagingOAuthAPIServer {
			operatorCopy := operator.DeepCopy()
			operatorCopy.Status.ManagingOAuthAPIServer = true
			_, err := authOperatorClient.Authentications().UpdateStatus(operatorCopy)
			return err
		}

		return nil
	})

	controllerFactory.WithInformers(authOperatorInformers.Operator().V1().Authentications().Informer())
	return controllerFactory.ToController(name, eventRecorder)
}
