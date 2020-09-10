package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/transport"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"
)

var kasServicePort int

func init() {
	(&sync.Once{}).Do(func() {
		var err error
		kasServicePort, err = strconv.Atoi(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
		if err != nil {
			klog.Warningf("Defaulting KUBERNETES_SERVICE_PORT_HTTPS to 443 due to parsing error: %v", err)
			kasServicePort = 443
		}
	})
}

type wellKnownReadyController struct {
	serviceLister   corev1lister.ServiceLister
	endpointLister  corev1lister.EndpointsLister
	operatorClient  v1helpers.OperatorClient
	authLister      configv1lister.AuthenticationLister
	configMapLister corev1lister.ConfigMapLister
	routeLister     routev1lister.RouteLister
}

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"WellKnownAvailable",
)

func NewWellKnownReadyController(kubeInformers v1helpers.KubeInformersForNamespaces, configInformers configinformer.SharedInformerFactory, routeInformer routeinformer.RouteInformer,
	operatorClient v1helpers.OperatorClient, recorder events.Recorder) factory.Controller {

	nsOpenshiftConfigManagedInformers := kubeInformers.InformersFor("openshift-config-managed")
	nsDefaultInformers := kubeInformers.InformersFor("default")

	c := &wellKnownReadyController{
		serviceLister:   nsDefaultInformers.Core().V1().Services().Lister(),
		endpointLister:  nsDefaultInformers.Core().V1().Endpoints().Lister(),
		authLister:      configInformers.Config().V1().Authentications().Lister(),
		configMapLister: nsOpenshiftConfigManagedInformers.Core().V1().ConfigMaps().Lister(),
		routeLister:     routeInformer.Lister(),
		operatorClient:  operatorClient,
	}

	return factory.New().WithInformers(
		nsDefaultInformers.Core().V1().Services().Informer(),
		nsDefaultInformers.Core().V1().Endpoints().Informer(),
		configInformers.Config().V1().Authentications().Informer(),
		nsOpenshiftConfigManagedInformers.Core().V1().ConfigMaps().Informer(),
		routeInformer.Informer(),
	).
		ResyncEvery(30*time.Second).
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController("WellKnownReadyController", recorder.WithComponentSuffix("wellknown-ready-controller"))
}

func (c *wellKnownReadyController) sync(ctx context.Context, controllerContext factory.SyncContext) error {
	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	authConfig, err := c.authLister.Get("cluster")
	if err != nil {
		return err
	}
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if apierrors.IsNotFound(err) {
		if _, _, updateErr := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:    "WellKnownAvailable",
			Status:  operatorv1.ConditionFalse,
			Reason:  "PrereqsNotReady",
			Message: err.Error(),
		})); updateErr != nil {
			utilruntime.HandleError(updateErr)
			// fall through to the generic error handling for degraded and requeue
		}
	}
	if err != nil {
		return err
	}

	if err := c.isWellknownEndpointsReady(operatorSpec, operatorStatus, authConfig, route); err != nil {
		_, _, updateErr := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:    "WellKnownAvailable",
			Status:  operatorv1.ConditionFalse,
			Reason:  "NotReady",
			Message: fmt.Sprintf("The well-known endpoint is not yet available: %s", err.Error()),
		}))
		if updateErr != nil {
			utilruntime.HandleError(updateErr)
			// fall through to the generic error handling for degraded and requeue
		}
		return err
	}

	_, _, updateErr := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
		Type:   "WellKnownAvailable",
		Status: operatorv1.ConditionTrue,
		Reason: "AsExpected",
	}))
	if updateErr != nil {
		return updateErr
	}
	return nil
}

func (c *wellKnownReadyController) isWellknownEndpointsReady(spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, authConfig *configv1.Authentication, route *routev1.Route) error {
	// don't perform this check when OAuthMetadata reference is set up
	// leave those cases to KAS-o which handles these cases
	// the operator manages the metadata if specifically requested and by default
	isOperatorManagedMetadata := authConfig.Spec.Type == configv1.AuthenticationTypeIntegratedOAuth || len(authConfig.Spec.Type) == 0
	if userMetadataConfig := authConfig.Spec.OAuthMetadata.Name; !isOperatorManagedMetadata || len(userMetadataConfig) != 0 {
		return nil
	}

	caData, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return fmt.Errorf("failed to read SA ca.crt: %v", err)
	}

	// pass the KAS service name for SNI
	rt, err := transport.TransportFor("kubernetes.default.svc", caData, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to build transport for SA ca.crt: %v", err)
	}

	ips, err := c.getAPIServerIPs()
	if err != nil {
		return fmt.Errorf("failed to get API server IPs: %v", err)
	}

	for _, ip := range ips {
		err := c.checkWellknownEndpointReady(ip, rt, route)
		if err != nil {
			return err
		}
	}

	// if we don't have the min number of masters, this is actually ok, however Clayton has draw a hardline on starting tests as soon as all operators are Available=true
	// while ignoring progressing=false.  This means that even though no external observer will see a invalid .well-known information,
	// the tests end up failing when their long lived connections are terminated.  Killing long lived connections is normal and
	// acceptable for the kube-apiserver to do during a rollout.  However, because we are not allowed to merge code that ensures
	// a stable kube-apiserver and because rewriting client tests like e2e-cmd is impractical, we are left trying to enforce
	// this by delaying our availability because it's a backdoor into slowing down the test suite start time to gain stability.
	alreadyTrueOnce := v1helpers.IsOperatorConditionTrue(status.Conditions, "WellKnownAvailable")
	if alreadyTrueOnce {
		// if we've already been true once, then we have confirmed matching well-known metadata, so CI no longer needs this protection.
		// this also prevents flapping after one success when the kube-apiserver rolls out again
		return nil
	}
	if expectedMinNumber := getExpectedMinimumNumberOfMasters(spec); len(ips) < expectedMinNumber {
		return fmt.Errorf("need at least %d kube-apiservers, got %d (see kube-apiserver operator for more information)", expectedMinNumber, len(ips))
	}

	return nil
}

func (c *wellKnownReadyController) checkWellknownEndpointReady(apiIP string, rt http.RoundTripper, route *routev1.Route) error {
	wellKnown := "https://" + apiIP + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("failed to build request to well-known %s: %v", wellKnown, err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("failed to GET well-known %s: %v", wellKnown, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("got '%s' status while trying to GET the OAuth well-known %s endpoint data", resp.Status, wellKnown)
	}

	var receivedValues map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read well-known %s body: %v", wellKnown, err)
	}
	if err := json.Unmarshal(body, &receivedValues); err != nil {
		return fmt.Errorf("failed to marshall well-known %s JSON: %v", wellKnown, err)
	}

	expectedMetadata, err := c.getOAuthMetadata()
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(expectedMetadata, receivedValues) {
		return fmt.Errorf("the value returned by the well-known %s endpoint does not match expectations", wellKnown)
	}

	return nil
}

func (c *wellKnownReadyController) getOAuthMetadata() (map[string]interface{}, error) {
	cm, err := c.configMapLister.ConfigMaps("openshift-config-managed").Get("oauth-openshift")
	if err != nil {
		return nil, err
	}

	metadataJSON, ok := cm.Data["oauthMetadata"]
	if !ok || len(metadataJSON) == 0 {
		return nil, fmt.Errorf("the openshift-config-managed/oauth-openshift configMap is missing data in the 'oauthMetadata' key")
	}

	var metadataStruct map[string]interface{}
	if err = json.Unmarshal([]byte(metadataJSON), &metadataStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cm metadata: %w", err)
	}

	return metadataStruct, nil
}

func getKASTargetPortFromService(service *corev1.Service) (int, bool) {
	for _, port := range service.Spec.Ports {
		if targetPort := port.TargetPort.IntValue(); targetPort != 0 && port.Protocol == corev1.ProtocolTCP && int(port.Port) == kasServicePort {
			return targetPort, true
		}
	}
	return 0, false
}

func subsetHasKASTargetPort(subset corev1.EndpointSubset, targetPort int) bool {
	for _, port := range subset.Ports {
		if port.Protocol == corev1.ProtocolTCP && int(port.Port) == targetPort {
			return true
		}
	}
	return false
}

func (c *wellKnownReadyController) getAPIServerIPs() ([]string, error) {
	kasService, err := c.serviceLister.Services(corev1.NamespaceDefault).Get("kubernetes")
	if err != nil {
		return nil, fmt.Errorf("failed to get kube api server service: %v", err)
	}

	targetPort, ok := getKASTargetPortFromService(kasService)
	if !ok {
		return nil, fmt.Errorf("unable to find kube api server service target port: %#v", kasService)
	}

	kasEndpoint, err := c.endpointLister.Endpoints(corev1.NamespaceDefault).Get("kubernetes")
	if err != nil {
		return nil, fmt.Errorf("failed to get kube api server endpointLister: %v", err)
	}

	for _, subset := range kasEndpoint.Subsets {
		if !subsetHasKASTargetPort(subset, targetPort) {
			continue
		}

		if len(subset.NotReadyAddresses) != 0 || len(subset.Addresses) == 0 {
			return nil, fmt.Errorf("kube api server endpointLister is not ready: %#v", kasEndpoint)
		}

		ips := make([]string, 0, len(subset.Addresses))
		for _, address := range subset.Addresses {
			ips = append(ips, net.JoinHostPort(address.IP, strconv.Itoa(targetPort)))
		}
		return ips, nil
	}

	return nil, fmt.Errorf("unable to find kube api server endpointLister port: %#v", kasEndpoint)
}
