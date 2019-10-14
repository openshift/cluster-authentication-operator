package oauthclientcontroller

import (
	"monis.app/go/openshift/controller"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	oauthv1 "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type EnsureOAuthClient func(oauthClient oauthclient.OAuthClientInterface, routeClient routeclient.RouteInterface, actualClient *oauthv1.OAuthClient) error

type oauthClientsController struct {
	operatorClient    v1helpers.OperatorClient
	routeClient       routeclient.RouteV1Interface
	oauthClientClient oauthclient.OAuthClientInterface

	clientEnsureMap map[string]EnsureOAuthClient

	eventRecorder events.Recorder
}

func NewOAuthClientsController(
	operatorClient v1helpers.OperatorClient,
	oauthClientClient oauthclient.OAuthClientInterface,
	oauthClientInformer oauthinformer.OAuthClientInformer,
	routeClient routeclient.RouteV1Interface,
	clientEnsureMap map[string]EnsureOAuthClient,
	eventRecorder events.Recorder,
) controller.Runner {
	c := oauthClientsController{
		operatorClient:    operatorClient,
		oauthClientClient: oauthClientClient,
		routeClient:       routeClient,

		clientEnsureMap: clientEnsureMap,

		eventRecorder: eventRecorder,
	}

	return controller.New("OAutClientsController", c)
}

func (c *oauthClientsController) Key(namespace, name string) (metav1.Object, error) {
	obj, err := c.oauthClientClient.Get(name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		return defaultOAuthClient(name), nil
	}
	return obj, err
}

func (c *oauthClientsController) Sync(obj metav1.Object) error {
	oauthClient := obj.(*oauthv1.OAuthClient)
	oauthClientCopy := oauthClient.DeepCopy()

	return c.clientEnsureMap[oauthClientCopy.Name](c.oauthClientClient, c.routeClient, oauthClientCopy)
}

// defaultOAuthClient returns a stub *OAuthClient object which should always trigger
// updates in the sync loop
func defaultOAuthClient(name string) *oauthv1.OAuthClient {
	// TODO: we may want a more general approach which would allow specifying a default func
	return &oauthv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}
