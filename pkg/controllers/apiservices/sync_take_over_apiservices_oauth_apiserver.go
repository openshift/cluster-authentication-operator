package apiservices

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorclientinformers "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// NewManageAPIServicesController sets ManagingOAuthAPIServer flag to true.
// This will make OpenShift APIServer to step down and traffic will be routed to the OAuth APIServer
//
// see https://github.com/openshift/enhancements/blob/master/enhancements/authentication/separate-oauth-resources.md
func NewManageAPIServicesController(
	name string,
	deployer statemachine.Deployer,
	authOperatorClient operatorconfigclient.AuthenticationsGetter,
	authOperatorInformers operatorclientinformers.SharedInformerFactory,
	eventRecorder events.Recorder) factory.Controller {

	controllerFactory := factory.New()
	authOperatorLister := authOperatorInformers.Operator().V1().Authentications().Lister()

	controllerFactory.WithSync(func(ctx context.Context, syncContext factory.SyncContext) error {
		operator, err := authOperatorLister.Get("cluster")
		if err != nil {
			return err
		}

		if !v1helpers.IsOperatorConditionTrue(operator.Status.Conditions, "Available") {
			message := "authentication operator is not Available"
			syncContext.Recorder().Warning("PrereqNotReady", message)
			return fmt.Errorf(message)
		}

		// on already encrypted cluster we need to wait until oauth-apiserver observers the encryption config before routing traffic to it
		// otherwise we won't be able to decrypt data (OAuth tokens)
		_, converged, err := deployer.DeployedEncryptionConfigSecret()
		if err != nil {
			return err
		}
		if !converged {
			syncContext.Recorder().Warning("PrereqNotReady", "the encryption deployer hasn't yet converged, retrying in 5 minutes")
			syncContext.Queue().AddAfter(syncContext.QueueKey(), 5*time.Minute)
			return nil
		}

		if !operator.Status.ManagingOAuthAPIServer {
			operatorCopy := operator.DeepCopy()
			operatorCopy.Status.ManagingOAuthAPIServer = true
			_, err := authOperatorClient.Authentications().UpdateStatus(ctx, operatorCopy, metav1.UpdateOptions{})
			return err
		}

		return nil
	})

	controllerFactory.WithInformers(authOperatorInformers.Operator().V1().Authentications().Informer())
	return controllerFactory.ToController(name, eventRecorder.WithComponentSuffix("mange-oauth-api-controller"))
}
