package routecontroller

import (
	"fmt"

	"monis.app/go/openshift/controller"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	routev1 "github.com/openshift/api/route/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerWorkQueueKey           = "key"
	conditionRouterCertsDegradedType = "RouterCertsDegraded"
)

// RouterCertsDomainValidationController validates that router certs match the ingress domain
type routeController struct {
	operatorClient    v1helpers.OperatorClient
	routeClient       routeclient.RouteV1Interface
	oauthClientClient oauthclient.OAuthClientInterface
	ingressLister     configv1listers.IngressLister

	routeToOAuthClientMap map[string][]OAuthClientExpectedRoute // TODO: should be (namespace,name) touple struct or similar

	eventRecorder events.Recorder
}

type OAuthClientExpectedRoute struct {
	OAuthClientName string
	URLFormat       string
}

func NewRouteController(
	operatorClient v1helpers.OperatorClient,
	oauthClientClient oauthclient.OAuthClientInterface,
	routeClient routeclient.RouteV1Interface,
	ingressInformer configv1informers.IngressInformer,
	routeInformer routeinformer.RouteInformer,
	routeToOAuthClientMap map[string][]OAuthClientExpectedRoute,
	eventRecorder events.Recorder,
) controller.Runner {
	c := &routeController{
		operatorClient:    operatorClient,
		oauthClientClient: oauthClientClient,
		routeClient:       routeClient,
		ingressLister:     ingressInformer.Lister(),

		routeToOAuthClientMap: routeToOAuthClientMap,

		eventRecorder: eventRecorder,
	}

	return controller.New("RouterController", c,
		controller.WithInformer(ingressInformer, controller.FilterByNames(
			// TODO: improve the controller framework so that it is capable of emiting multiple events on one obj change
			//       if we want to have `change -> sync N parent objects` relations
			func(_ metav1.Object) (string, string) { return "openshift-authentication", "oauth-openshift" },
			"cluster"),
		),
		controller.WithInformer(routeInformer, WatchAllFilter()),
	)
}

func (c *routeController) Key(namespace, name string) (metav1.Object, error) {
	obj, err := c.routeClient.Routes(namespace).Get(name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		obj, err = c.routeClient.Routes(namespace).Create(defaultRouteNoHost(name)) // FIXME: this is so wrong
	}
	return obj, err
}

func (c *routeController) Sync(obj metav1.Object) error {
	route := obj.(*routev1.Route)

	spec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if !management.IsOperatorManaged(spec.ManagementState) {
		return nil
	}

	ingress, err := c.ingressLister.Get("cluster")
	if err != nil {
		return fmt.Errorf("failed getting the ingress config: %v", err)
	}

	routeCopy := route.DeepCopy()
	//route, routeSecret, reason, err := c.handleRoute(ingress)
	routeNew, _, err := c.handleRoute(c.routeClient.Routes(routeCopy.Namespace), ingress, routeCopy)
	if err != nil {
		return fmt.Errorf("failed getting the route: %v", err)
	}

	err = c.handleOAuthClients(routeNew)
	if err != nil {
		return fmt.Errorf("failed handling OAuthClients: %v", err)
	}
	return nil
}

func (c *routeController) handleOAuthClients(route *routev1.Route) error {
	var err error
	for _, clientExpect := range c.routeToOAuthClientMap[route.Name] {
		client, err := c.oauthClientClient.Get(clientExpect.OAuthClientName, metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
			klog.Infof("OAuthClient '%s' not found", clientExpect.OAuthClientName)
			continue
		}
		expectedURI := fmt.Sprintf(clientExpect.URLFormat, route.Spec.Host)
		found := false
		for _, uri := range client.RedirectURIs {
			if uri == expectedURI {
				found = true
				break
			}
		}
		if !found {
			clientCopy := client.DeepCopy()
			clientCopy.RedirectURIs = append(clientCopy.RedirectURIs, expectedURI)
			_, err = c.oauthClientClient.Update(clientCopy)
		}
	}
	return err
}

// TODO: this is probably wrong and some other options from the controller package should be used
func WatchAllFilter() controller.ParentFilter {
	disregardInput := func(_ metav1.Object) bool { return true }
	disregardInputUpdate := func(_, _ metav1.Object) bool { return true }
	return controller.FilterFuncs{
		ParentFunc: nil,
		AddFunc:    disregardInput,
		UpdateFunc: disregardInputUpdate,
		DeleteFunc: disregardInput,
	}
}

// FIXME: move to apis/
func defaultMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:            "oauth-openshift",
		Namespace:       "openshift-authentication",
		Labels:          defaultLabels(),
		Annotations:     map[string]string{},
		OwnerReferences: nil, // TODO
	}
}

func defaultLabels() map[string]string {
	return map[string]string{
		"app": "oauth-openshift",
	}
}

// -------------
