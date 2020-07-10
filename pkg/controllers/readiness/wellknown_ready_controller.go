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
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/transport"
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
	"WellKnownRouteDegraded",
	"WellKnownAuthConfigDegraded",
	"WellKnownProgressing",
	"WellKnownAvailable",
)

func NewWellKnownReadyController(kubeInformersNamespaced informers.SharedInformerFactory, configInformers configinformer.SharedInformerFactory, routeInformer routeinformer.RouteInformer,
	operatorClient v1helpers.OperatorClient, recorder events.Recorder) factory.Controller {
	c := &wellKnownReadyController{
		serviceLister:   kubeInformersNamespaced.Core().V1().Services().Lister(),
		endpointLister:  kubeInformersNamespaced.Core().V1().Endpoints().Lister(),
		authLister:      configInformers.Config().V1().Authentications().Lister(),
		configMapLister: kubeInformersNamespaced.Core().V1().ConfigMaps().Lister(),
		routeLister:     routeInformer.Lister(),
		operatorClient:  operatorClient,
	}

	return factory.New().ResyncEvery(30*time.Second).WithInformers(
		kubeInformersNamespaced.Core().V1().Services().Informer(),
		kubeInformersNamespaced.Core().V1().Endpoints().Informer(),
		configInformers.Config().V1().Authentications().Informer(),
		routeInformer.Informer(),
	).WithSync(c.sync).ToController("WellKnownReadyController", recorder.WithComponentSuffix("wellknown-ready-controller"))
}

func (c *wellKnownReadyController) sync(ctx context.Context, controllerContext factory.SyncContext) error {
	foundConditions := []operatorv1.OperatorCondition{}

	authConfig, configConditions := common.GetAuthConfig(c.authLister, "WellKnownAuthConfig")
	foundConditions = append(foundConditions, configConditions...)

	route, routeConditions := common.GetOAuthServerRoute(c.routeLister, "WellKnownRoute")
	foundConditions = append(foundConditions, routeConditions...)

	if authConfig != nil && route != nil {
		// TODO: refactor this to return conditions
		ready, conditionMessage, err := c.isWellknownEndpointsReady(authConfig, route)
		if !ready {
			if len(conditionMessage) == 0 && err != nil {
				conditionMessage = err.Error()
			}
			if len(conditionMessage) > 0 {
				foundConditions = append(foundConditions, operatorv1.OperatorCondition{
					Type:    "WellKnownProgressing",
					Status:  operatorv1.ConditionTrue,
					Reason:  "NotReady",
					Message: fmt.Sprintf("The well-known endpoint is not yet avaiable: %s", conditionMessage),
				})
				foundConditions = append(foundConditions, operatorv1.OperatorCondition{
					Type:    "WellKnownAvailable",
					Status:  operatorv1.ConditionFalse,
					Reason:  "NotReady",
					Message: fmt.Sprintf("THe well-known endpoint is not yet available: %s", conditionMessage),
				})
			}
		}
	}

	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}
	for _, conditionType := range knownConditionNames.List() {
		// clean up existing foundConditions
		updatedCondition := operatorv1.OperatorCondition{
			Type:   conditionType,
			Status: operatorv1.ConditionFalse,
		}
		if strings.HasSuffix(conditionType, "Available") {
			updatedCondition.Status = operatorv1.ConditionTrue
		}
		if condition := v1helpers.FindOperatorCondition(foundConditions, conditionType); condition != nil {
			updatedCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(updatedCondition))
	}
	if _, _, err := v1helpers.UpdateStatus(c.operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	return nil
}

func (c *wellKnownReadyController) isWellknownEndpointsReady(authConfig *configv1.Authentication, route *routev1.Route) (bool, string, error) {
	// don't perform this check when OAuthMetadata reference is set up
	// leave those cases to KAS-o which handles these cases
	if userMetadataConfig := authConfig.Spec.OAuthMetadata.Name; authConfig.Spec.Type != configv1.AuthenticationTypeIntegratedOAuth || len(userMetadataConfig) != 0 {
		return true, "", nil
	}

	caData, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return false, "", fmt.Errorf("failed to read SA ca.crt: %v", err)
	}

	// pass the KAS service name for SNI
	rt, err := transport.TransportFor("kubernetes.default.svc", caData, nil, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to build transport for SA ca.crt: %v", err)
	}

	ips, err := c.getAPIServerIPs()
	if err != nil {
		return false, "", fmt.Errorf("failed to get API server IPs: %v", err)
	}

	for _, ip := range ips {
		wellknownReady, wellknownMsg, err := c.checkWellknownEndpointReady(ip, rt, route)
		if err != nil || !wellknownReady {
			return wellknownReady, wellknownMsg, err
		}
	}

	return true, "", nil
}

func (c *wellKnownReadyController) checkWellknownEndpointReady(apiIP string, rt http.RoundTripper, route *routev1.Route) (bool, string, error) {
	wellKnown := "https://" + apiIP + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to build request to well-known %s: %v", wellKnown, err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return false, "", fmt.Errorf("failed to GET well-known %s: %v", wellKnown, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("got '%s' status while trying to GET the OAuth well-known %s endpoint data", resp.Status, wellKnown), nil
	}

	var receivedValues map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read well-known %s body: %v", wellKnown, err)
	}
	if err := json.Unmarshal(body, &receivedValues); err != nil {
		return false, "", fmt.Errorf("failed to marshall well-known %s JSON: %v", wellKnown, err)
	}

	expectedMetadata, err := c.getOAuthMetadata()
	if err != nil {
		return false, "", err
	}

	if !reflect.DeepEqual(expectedMetadata, receivedValues) {
		return false, fmt.Sprintf("the value returned by the well-known %s endpoint does not match expectations", wellKnown), nil
	}

	return true, "", nil
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
