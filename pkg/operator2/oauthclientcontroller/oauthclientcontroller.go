package oauthclientcontroller

import (
	"monis.app/go/openshift/controller"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	oauthv1 "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type oauthClientsController struct {
	operatorClient    v1helpers.OperatorClient
	routeClient       routeclient.RouteV1Interface
	oauthClientClient oauthclient.OAuthClientInterface

	eventRecorder events.Recorder
}

func NewOAuthClientsController(
	operatorClient v1helpers.OperatorClient,
	oauthClientClient oauthclient.OAuthClientInterface,
	oauthClientInformer oauthinformer.OAuthClientInformer,
	routeClient routeclient.RouteV1Interface,
) controller.Runner {
	c := oauthClientsController{
		operatorClient:    operatorClient,
		oauthClientClient: oauthClientClient,
		routeClient:       routeClient,
	}

	return controller.New("OAutClientsController", c)
}

func (c *oauthClientsController) Key(namespace, name string) (metav1.Object, error) {
	return c.oauthClientClient.Get(name, metav1.GetOptions{})
}

func (c *oauthClientsController) Sync(obj metav1.Object) error {
	_ = obj.(*oauthv1.OAuthClient)

	return nil
}
