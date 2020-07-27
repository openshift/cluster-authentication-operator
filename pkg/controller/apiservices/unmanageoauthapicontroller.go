package apiservices

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorclientinformers "github.com/openshift/client-go/operator/informers/externalversions"
	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

// NewUnmanageAPIServicesController sets ManagingOAuthAPIServer flag to false.
// This will make OAuth APIServer (introduced in 4.6) to step down and traffic
// will be routed to the OpenShift APIServer. It's a measure required for 4.6->4.5
// downgrade.
//
// see https://github.com/openshift/enhancements/blob/master/enhancements/authentication/separate-oauth-resources.md
func NewUnmanageAPIServicesController(
	name string,
	authOperatorClient operatorconfigclient.AuthenticationsGetter,
	authOperatorInformers operatorclientinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
) factory.Controller {

	authInformers := authOperatorInformers.Operator().V1().Authentications()
	return factory.New().
		WithSync(syncUnmanageAPIServicesController(name, authOperatorClient, authInformers.Lister())).
		WithInformers(authInformers.Informer()).
		ToController(name, eventRecorder.WithComponentSuffix("unmanage-oauth-api-controller"))
}

func syncUnmanageAPIServicesController(controllerName string, authOperatorClient operatorconfigclient.AuthenticationsGetter, authOperatorLister operatorlistersv1.AuthenticationLister) factory.SyncFunc {
	return func(ctx context.Context, syncContext factory.SyncContext) error {
		operator, err := authOperatorLister.Get("cluster")
		if err != nil {
			return err
		}

		if operator.Status.ManagingOAuthAPIServer {
			operatorCopy := operator.DeepCopy()
			operatorCopy.Status.ManagingOAuthAPIServer = false
			_, err = authOperatorClient.Authentications().UpdateStatus(ctx, operatorCopy, metav1.UpdateOptions{})
			if err == nil {
				syncContext.Recorder().Eventf(controllerName, "turned OAuth API managing off")
			}
		}

		return err
	}
}
