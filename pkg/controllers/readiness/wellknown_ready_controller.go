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

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/transport"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	netutil "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
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
	controllerInstanceName string
	serviceLister          corev1lister.ServiceLister
	endpointLister         corev1lister.EndpointsLister
	operatorClient         v1helpers.OperatorClient
	authLister             configv1lister.AuthenticationLister
	configMapLister        corev1lister.ConfigMapLister
	routeLister            routev1lister.RouteLister
	infrastructureLister   configv1lister.InfrastructureLister
	authConfigChecker      common.AuthConfigChecker
}

const controllerName = "WellKnownReadyController"

func NewWellKnownReadyController(
	instanceName string,
	kubeInformers v1helpers.KubeInformersForNamespaces,
	configInformers configinformer.SharedInformerFactory,
	routeInformer routeinformer.RouteInformer,
	operatorClient v1helpers.OperatorClient,
	authConfigChecker common.AuthConfigChecker,
	recorder events.Recorder,
) factory.Controller {

	nsOpenshiftConfigManagedInformers := kubeInformers.InformersFor("openshift-config-managed")
	nsDefaultInformers := kubeInformers.InformersFor("default")

	c := &wellKnownReadyController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "WellKnownReady"),
		serviceLister:          nsDefaultInformers.Core().V1().Services().Lister(),
		endpointLister:         nsDefaultInformers.Core().V1().Endpoints().Lister(),
		authLister:             configInformers.Config().V1().Authentications().Lister(),
		infrastructureLister:   configInformers.Config().V1().Infrastructures().Lister(),
		configMapLister:        nsOpenshiftConfigManagedInformers.Core().V1().ConfigMaps().Lister(),
		routeLister:            routeInformer.Lister(),
		operatorClient:         operatorClient,
		authConfigChecker:      authConfigChecker,
	}

	return factory.New().WithInformers(
		nsDefaultInformers.Core().V1().Services().Informer(),
		nsDefaultInformers.Core().V1().Endpoints().Informer(),
		configInformers.Config().V1().Authentications().Informer(),
		configInformers.Config().V1().Infrastructures().Informer(),
		nsOpenshiftConfigManagedInformers.Core().V1().ConfigMaps().Informer(),
		routeInformer.Informer(),
	).
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController(
			controllerName, // Don't change what is passed here unless you also remove the old FooDegraded condition
			recorder.WithComponentSuffix("wellknown-ready-controller"))
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
	infraConfig, err := c.infrastructureLister.Get("cluster")
	if err != nil {
		return err
	}

	// the code below this point triggers status updates, unify status update handling in defer
	status := applyoperatorv1.OperatorStatus()

	// create conditions to be applied during defer. These conditions are intentionally left without a status,
	// ensuring the API server will reject the Apply operation if the status is not set down below
	available := applyoperatorv1.OperatorCondition().
		WithType("WellKnownAvailable")
	progressing := applyoperatorv1.OperatorCondition().
		WithType(common.ControllerProgressingConditionName(controllerName))

	// if OIDC is enabled, clear operator conditions and skip checks
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		// Server-Side-Apply with an empty operator status for the specific field manager
		// will effectively remove any conditions owned by it since the list type in the
		// API definition is 'map'
		return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, applyoperatorv1.OperatorStatus())
	}

	defer func() {
		status = status.WithConditions(available, progressing)
		if updateErr := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); updateErr != nil {
			// fall through to the generic error handling for degraded and requeue
			utilruntime.HandleError(updateErr)
		}
	}()

	// the well-known endpoint cannot be ready until we know the oauth-server's hostname
	_, err = c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if apierrors.IsNotFound(err) {
		available = available.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("PrereqsNotReady").
			WithMessage(err.Error())
		progressing = progressing.
			WithStatus(operatorv1.ConditionTrue)
		return err
	}
	if err != nil {
		available = available.
			WithStatus(operatorv1.ConditionUnknown).
			WithReason("SyncError").
			WithMessage(err.Error())
		progressing = progressing.
			WithStatus(operatorv1.ConditionUnknown)
		return err
	}

	if err := c.isWellknownEndpointsReady(ctx, operatorSpec, operatorStatus, authConfig, infraConfig); err != nil {
		available = available.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("NotReady").
			WithMessage(fmt.Sprintf("The well-known endpoint is not yet available: %s", err.Error()))
		progressing = progressing.
			WithStatus(operatorv1.ConditionTrue)
		if progressingErr, ok := err.(*common.ControllerProgressingError); ok {
			if progressingErr.IsDegraded(controllerName, operatorStatus) {
				return progressingErr.Unwrap()
			}
			progressing = progressingErr.ToCondition(controllerName)
			return nil
		} else {
			return err
		}
	}

	progressing = progressing.
		WithStatus(operatorv1.ConditionFalse)
	available = available.
		WithStatus(operatorv1.ConditionTrue).
		WithReason("AsExpected")

	return nil
}

func (c *wellKnownReadyController) isWellknownEndpointsReady(ctx context.Context, spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, authConfig *configv1.Authentication, infraConfig *configv1.Infrastructure) error {
	// don't perform this check when OAuthMetadata reference is set up
	// leave those cases to KAS-o which handles these cases
	// the operator manages the metadata if specifically requested and by default
	isOperatorManagedMetadata := authConfig.Spec.Type == configv1.AuthenticationTypeIntegratedOAuth || len(authConfig.Spec.Type) == 0
	if userMetadataConfig := authConfig.Spec.OAuthMetadata.Name; !isOperatorManagedMetadata || len(userMetadataConfig) != 0 {
		return nil
	}

	caData, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
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
		return fmt.Errorf("failed to get API server IPs: %v (check kube-apiserver that it deploys correctly)", err)
	}

	for _, ip := range ips {
		err := c.checkWellknownEndpointReady(ctx, ip, rt)
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

	if expectedMinNumber := getExpectedMinimumNumberOfMasters(spec, infraConfig.Status.ControlPlaneTopology); len(ips) < expectedMinNumber {
		return fmt.Errorf("need at least %d kube-apiservers, got %d", expectedMinNumber, len(ips))
	}

	return nil
}

func (c *wellKnownReadyController) checkWellknownEndpointReady(ctx context.Context, apiIP string, rt http.RoundTripper) error {
	expectedMetadata, err := c.getOAuthMetadata()
	if err != nil {
		return fmt.Errorf("failed to get oauth metadata from openshift-config-managed/oauth-openshift ConfigMap: %w (check authentication operator, it is supposed to create this)", err)
	}
	wellKnown := "https://" + apiIP + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("failed to build request to well-known %s: %v", wellKnown, err)
	}

	var connError error
	var resp *http.Response
	for i := 0; i < 3; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		req := req.WithContext(reqCtx)
		resp, err = rt.RoundTrip(req)
		if err != nil {
			connError = fmt.Errorf("failed to GET kube-apiserver oauth endpoint %s: %w%s", wellKnown, err, wellKnownRoundtripErrorHint(err))
			klog.V(2).Info(connError)
			continue
		}
		connError = nil
		defer resp.Body.Close()
		break
	}

	if connError != nil {
		return connError
	}

	switch resp.StatusCode {
	case 200:
		// success
	case http.StatusNotFound:
		return common.NewControllerProgressingError("OAuthMetadataNotYetServed", fmt.Errorf("kube-apiserver oauth endpoint %s is not yet served and authentication operator keeps waiting (check kube-apiserver operator, and check that instances roll out successfully, which can take several minutes per instance)", wellKnown), 5*time.Minute)
	default:
		return fmt.Errorf("kube-apiserver oauth endpoint %s replied with unexpected status: %s (check kube-apiserver logs if this error persists)", wellKnown, resp.Status)
	}

	var receivedValues map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read %s body: %v (check kube-apiserver logs if this error persists)", wellKnown, err)
	}
	if err := json.Unmarshal(body, &receivedValues); err != nil {
		return fmt.Errorf("failed to unmarshal %s JSON: %v (check kube-apiserver logs if this error persists)", wellKnown, err)
	}

	if !reflect.DeepEqual(expectedMetadata, receivedValues) {
		return common.NewControllerProgressingError("OAuthMetadataDiffer", fmt.Errorf("the %s endpoint returns different oauth metadata than is stored in openshift-config-managed/oauth-openshift ConfigMap (check kube-apiserver operator that instances roll out, which happens when oauth metadata changes)", wellKnown), 5*time.Minute)
	}

	return nil
}

func wellKnownRoundtripErrorHint(err error) string {
	switch {
	case isConnectionRefusedError(err) || netutil.IsConnectionRefused(err):
		return " (kube-apiserver is probably not running on that node, killed before graceful termination or crash-looping)"
	case netutil.IsNoRoutesError(err):
		return " (check node networking, the SDN might have stale routing information for pod IPs on that node)"
	case netutil.IsConnectionReset(err), netutil.IsProbableEOF(err), netutil.IsConnectionReset(err):
		return " (check cluster networking, it might be temporarily unstable)"
	case errors.IsServerTimeout(err), errors.IsTooManyRequests(err):
		return " (check kube-apiserver on that node, it might be under too heavy load)"
	case strings.Contains(err.Error(), ":53"):
		return " (check DNS on that node)"
	default:
		return ""
	}
}

func isConnectionRefusedError(err error) bool {
	return strings.Contains(err.Error(), "connection refused")
}

func (c *wellKnownReadyController) getOAuthMetadata() (map[string]interface{}, error) {
	cm, err := c.configMapLister.ConfigMaps("openshift-config-managed").Get("oauth-openshift")
	if err != nil {
		return nil, err
	}

	metadataJSON, ok := cm.Data["oauthMetadata"]
	if !ok || len(metadataJSON) == 0 {
		return nil, common.NewControllerProgressingError("NoOAuthMetadata", fmt.Errorf("the openshift-config-managed/oauth-openshift configMap is missing data in the 'oauthMetadata' key"), time.Minute)
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
