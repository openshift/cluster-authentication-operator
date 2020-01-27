package authconfig

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/client"
	"github.com/openshift/cluster-authentication-operator/pkg/utils"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var kasServicePort int

func init() {
	var err error
	kasServicePort, err = strconv.Atoi(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if err != nil {
		klog.Infof("defaulting KAS service port to 443 due to parsing error: %v", err)
		kasServicePort = 443
	}
}

type AuthenticationConfigController struct {
	operatorClient *client.OperatorClient
	authentication configv1client.AuthenticationInterface
	services       corev1client.ServicesGetter
	endpoints      corev1client.EndpointsGetter
	route          routeclient.RouteInterface
}

func NewAuthenticationConfigController(
	configClient configclient.Interface,
	kubeClient kubernetes.Interface,
	routeClient routeclient.RouteV1Interface,
	operatorClient *client.OperatorClient,
	eventsRecorder events.Recorder) factory.Controller {
	c := &AuthenticationConfigController{
		operatorClient: operatorClient,
		authentication: configClient.ConfigV1().Authentications(),
		route:          routeClient.Routes("openshift-authentication"),
		services:       kubeClient.CoreV1(),
		endpoints:      kubeClient.CoreV1(),
	}
	return factory.New().
		WithInformers(c.operatorClient.Informer()).
		WithSync(c.sync).
		ToController("AuthenticationConfigController", eventsRecorder)
}

func (c *AuthenticationConfigController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	authConfigNoDefaults, err := c.authentication.Get("cluster", metav1.GetOptions{})
	if err != nil {
		return err
	}

	route, err := c.route.Get("oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return err
	}

	expectedReference := configv1.ConfigMapNameReference{
		Name: "oauth-openshift",
	}

	if authConfigNoDefaults.Status.IntegratedOAuthMetadata == expectedReference {
		return nil
	}

	authConfigNoDefaults.Status.IntegratedOAuthMetadata = expectedReference
	_, err = c.authentication.UpdateStatus(authConfigNoDefaults)
	if err != nil {
		return err
	}

	prefix := "WellKnownEndpoint"
	var statusUpdateFuncs []v1helpers.UpdateStatusFunc
	wellKnownReady, wellKnownMsg, err := c.checkWellknownEndpointsReady(authConfigNoDefaults, route)
	if err != nil {
		statusUpdateFuncs = append(statusUpdateFuncs, v1helpers.UpdateConditionFn(
			operatorv1.OperatorCondition{
				Type:    prefix + operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "Error",
				Message: err.Error(),
			}))
	} else {
		statusUpdateFuncs = append(statusUpdateFuncs, v1helpers.UpdateConditionFn(
			operatorv1.OperatorCondition{
				Type:   prefix + operatorv1.OperatorStatusTypeDegraded,
				Status: operatorv1.ConditionFalse,
			}))
	}

	if !wellKnownReady {
		statusUpdateFuncs = append(statusUpdateFuncs, v1helpers.UpdateConditionFn(
			operatorv1.OperatorCondition{
				Type:    prefix + operatorv1.OperatorStatusTypeProgressing,
				Status:  operatorv1.ConditionTrue,
				Reason:  "WellKnownNotReady",
				Message: wellKnownMsg,
			}))
		statusUpdateFuncs = append(statusUpdateFuncs, v1helpers.UpdateConditionFn(
			operatorv1.OperatorCondition{
				Type:   prefix + operatorv1.OperatorStatusTypeAvailable,
				Status: operatorv1.ConditionFalse,
			}))
	}

	if _, _, err := v1helpers.UpdateStatus(c.operatorClient, statusUpdateFuncs...); err != nil {
		return err
	}

	return nil
}

func (c *AuthenticationConfigController) checkWellknownEndpointsReady(authConfig *configv1.Authentication, route *routev1.Route) (bool, string, error) {
	// TODO: don't perform this check when OAuthMetadata reference is set up,
	// the code in configmap.go does not handle such cases yet
	if len(authConfig.Spec.OAuthMetadata.Name) != 0 || authConfig.Spec.Type != configv1.AuthenticationTypeIntegratedOAuth {
		return true, "", nil
	}

	caData, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return false, "", fmt.Errorf("failed to read SA ca.crt: %v", err)
	}

	// pass the KAS service name for SNI
	rt, err := utils.TransportFor("kubernetes.default.svc", caData, nil, nil)
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

func (c *AuthenticationConfigController) checkWellknownEndpointReady(apiIP string, rt http.RoundTripper, route *routev1.Route) (bool, string, error) {
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

	expectedMetadata := utils.GetExpectedOAuthServerCapabilities(route)
	if !reflect.DeepEqual(expectedMetadata, receivedValues) {
		return false, fmt.Sprintf("the value returned by the well-known %s endpoint does not match expectations", wellKnown), nil
	}

	return true, "", nil
}

func (c *AuthenticationConfigController) getAPIServerIPs() ([]string, error) {
	kasService, err := c.services.Services(corev1.NamespaceDefault).Get("kubernetes", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kube api server service: %v", err)
	}

	targetPort, ok := getKASTargetPortFromService(kasService)
	if !ok {
		return nil, fmt.Errorf("unable to find kube api server service target port: %#v", kasService)
	}

	kasEndpoint, err := c.endpoints.Endpoints(corev1.NamespaceDefault).Get("kubernetes", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kube api server endpoints: %v", err)
	}

	for _, subset := range kasEndpoint.Subsets {
		if !subsetHasKASTargetPort(subset, targetPort) {
			continue
		}

		if len(subset.NotReadyAddresses) != 0 || len(subset.Addresses) == 0 {
			return nil, fmt.Errorf("kube api server endpoints is not ready: %#v", kasEndpoint)
		}

		ips := make([]string, 0, len(subset.Addresses))
		for _, address := range subset.Addresses {
			ips = append(ips, net.JoinHostPort(address.IP, strconv.Itoa(targetPort)))
		}
		return ips, nil
	}

	return nil, fmt.Errorf("unable to find kube api server endpoints port: %#v", kasEndpoint)
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
