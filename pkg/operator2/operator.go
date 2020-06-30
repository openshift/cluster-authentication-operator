package operator2

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"monis.app/go/openshift/controller"
	"monis.app/go/openshift/operator"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/transport"
)

// static environment variables from operator deployment
var (
	oauthserverVersion = os.Getenv("OPERAND_IMAGE_VERSION")
	operatorVersion    = os.Getenv("OPERATOR_IMAGE_VERSION")

	kasServicePort int
)

func init() {
	var err error
	kasServicePort, err = strconv.Atoi(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if err != nil {
		klog.Infof("defaulting KAS service port to 443 due to parsing error: %v", err)
		kasServicePort = 443
	}
}

type authOperator struct {
	authOperatorConfigClient OperatorClient

	versionGetter status.VersionGetter
	recorder      events.Recorder

	route routeclient.RouteInterface

	oauthClientClient oauthclient.OAuthClientInterface

	services    corev1client.ServicesGetter
	endpoints   corev1client.EndpointsGetter
	secrets     corev1client.SecretsGetter
	configMaps  corev1client.ConfigMapsGetter
	deployments appsv1client.DeploymentsGetter

	authentication configv1client.AuthenticationInterface
	oauth          configv1client.OAuthInterface
	console        configv1client.ConsoleInterface
	infrastructure configv1client.InfrastructureInterface
	ingress        configv1client.IngressInterface
	apiserver      configv1client.APIServerInterface
	proxy          configv1client.ProxyInterface

	systemCABundle []byte

	resourceSyncer resourcesynccontroller.ResourceSyncer
}

func NewAuthenticationOperator(
	authOpConfigClient OperatorClient,
	oauthClientClient oauthclient.OauthV1Interface,
	kubeInformersNamespaced informers.SharedInformerFactory,
	kubeSystemNamespaceInformers informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	routeInformer routeinformer.RouteInformer,
	routeClient routeclient.RouteV1Interface,
	configInformers configinformer.SharedInformerFactory,
	configClient configclient.Interface,
	versionGetter status.VersionGetter,
	recorder events.Recorder,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
) operator.Runner {
	c := &authOperator{
		authOperatorConfigClient: authOpConfigClient,

		versionGetter: versionGetter,
		recorder:      recorder,

		route: routeClient.Routes("openshift-authentication"),

		oauthClientClient: oauthClientClient.OAuthClients(),

		services:    kubeClient.CoreV1(),
		endpoints:   kubeClient.CoreV1(),
		secrets:     kubeClient.CoreV1(),
		configMaps:  kubeClient.CoreV1(),
		deployments: kubeClient.AppsV1(),

		authentication: configClient.ConfigV1().Authentications(),
		oauth:          configClient.ConfigV1().OAuths(),
		console:        configClient.ConfigV1().Consoles(),
		infrastructure: configClient.ConfigV1().Infrastructures(),
		ingress:        configClient.ConfigV1().Ingresses(),
		apiserver:      configClient.ConfigV1().APIServers(),
		proxy:          configClient.ConfigV1().Proxies(),

		resourceSyncer: resourceSyncer,
	}

	systemCABytes, err := ioutil.ReadFile("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	if err != nil {
		klog.Warningf("Unable to read system CA from /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem: %v", err)
	}
	c.systemCABundle = systemCABytes

	coreInformers := kubeInformersNamespaced.Core().V1()
	configV1Informers := configInformers.Config().V1()

	targetNameFilter := operator.FilterByNames("oauth-openshift")
	kubeadminNameFilter := operator.FilterByNames("kubeadmin")
	configNameFilter := operator.FilterByNames("cluster")
	prefixFilter := getPrefixFilter()

	return operator.New("AuthenticationOperator2", c,
		operator.WithInformer(routeInformer, targetNameFilter),
		operator.WithInformer(coreInformers.Services(), targetNameFilter),
		operator.WithInformer(kubeInformersNamespaced.Apps().V1().Deployments(), targetNameFilter),

		operator.WithInformer(coreInformers.Secrets(), prefixFilter),
		operator.WithInformer(coreInformers.ConfigMaps(), prefixFilter),

		operator.WithInformer(kubeSystemNamespaceInformers.Core().V1().Secrets(), kubeadminNameFilter),

		operator.WithInformer(authOpConfigClient.Informers.Operator().V1().Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.OAuths(), configNameFilter),
		operator.WithInformer(configV1Informers.Consoles(), configNameFilter, controller.WithNoSync()),
		operator.WithInformer(configV1Informers.Infrastructures(), configNameFilter, controller.WithNoSync()),
		operator.WithInformer(configV1Informers.Ingresses(), configNameFilter, controller.WithNoSync()),
		operator.WithInformer(configV1Informers.APIServers(), configNameFilter, controller.WithNoSync()),
		operator.WithInformer(configV1Informers.Proxies(), configNameFilter, controller.WithNoSync()),
	)
}

func (c *authOperator) Key() (metav1.Object, error) {
	return c.authOperatorConfigClient.Client.Authentications().Get(context.TODO(), "cluster", metav1.GetOptions{})
}

func (c *authOperator) Sync(obj metav1.Object) error {
	operatorConfig := obj.(*operatorv1.Authentication)

	if operatorConfig.Spec.ManagementState != operatorv1.Managed {
		return nil // TODO do something better for all states
	}

	operatorConfigCopy := operatorConfig.DeepCopy()

	conditions := newAuthConditions()
	syncErr := c.handleSync(context.TODO(), operatorConfigCopy, conditions)
	// this is a catch all degraded state that we only set when we are otherwise not degraded
	globalDegradedErr := syncErr
	if conditions.hasDegraded {
		globalDegradedErr = nil // unset because we are already degraded for some other reason
	}
	conditions.handleDegraded("OperatorSync", globalDegradedErr)

	if _, _, err := v1helpers.UpdateStatus(c.authOperatorConfigClient, func(status *operatorv1.OperatorStatus) error {
		// store a copy of our starting conditions, we need to preserve last transition time
		originalConditions := status.DeepCopy().Conditions

		// copy over everything else
		operatorConfigCopy.Status.OperatorStatus.DeepCopyInto(status)

		// restore the starting conditions
		status.Conditions = originalConditions

		// manually update the conditions while preserving last transition time
		for _, condition := range conditions.conditions {
			v1helpers.SetOperatorCondition(&status.Conditions, condition)
		}

		return nil
	}); err != nil {
		klog.Errorf("failed to update status: %v", err)
		if syncErr == nil {
			syncErr = err
		}
	}

	return syncErr
}

func waitForControllerComplete(name string, conditions []operatorv1.OperatorCondition) error {
	c := v1helpers.FindOperatorCondition(conditions, "Auth"+name+"Progressing")
	if c == nil {
		return fmt.Errorf(name + " progressing condition not found")
	}
	if c.Status == operatorv1.ConditionTrue {
		return fmt.Errorf("operator is still working towards " + name)
	}
	return nil
}

func (c *authOperator) handleSync(ctx context.Context, operatorConfig *operatorv1.Authentication, conditions *authConditions) error {
	_, operatorStatus, _, err := c.authOperatorConfigClient.GetOperatorState()
	if err != nil {
		return err
	}
	// The BLOCK sections are highly order dependent

	// ==================================
	// BLOCK 1: Metadata
	// ==================================
	//
	// Wait for the controller to report complete (progressing=false).
	// This is used to keep the ordering, until we break the ordering.
	if err := waitForControllerComplete("Metadata", operatorStatus.Conditions); err != nil {
		return err
	}

	// ==================================
	// BLOCK 2: service and service-ca data
	// ==================================
	//
	// Wait for the controller to report complete (progressing=false).
	// This is used to keep the ordering, until we break the ordering.
	if err := waitForControllerComplete("ServiceCA", operatorStatus.Conditions); err != nil {
		return err
	}

	// ==================================
	// BLOCK 3: build cli config
	// ==================================
	//
	// Wait for the controller to report complete (progressing=false).
	// This is used to keep the ordering, until we break the ordering.
	if err := waitForControllerComplete("CLIConfig", operatorStatus.Conditions); err != nil {
		return err
	}

	// ==================================
	// BLOCK 4: deployment
	// ==================================
	//
	// Wait for the controller to report complete (progressing=false).
	// This is used to keep the ordering, until we break the ordering.
	if err := waitForControllerComplete("Deployment", operatorStatus.Conditions); err != nil {
		return err
	}

	authConfig, err := c.authentication.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get auth config: %v", err)
	}
	routerSecret, err := c.secrets.Secrets("openshift-authentication").Get(ctx, "v4-0-config-system-router-certs", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get router secret: %v", err)
	}
	ingress, err := c.ingress.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get ingress: %v", err)
	}
	deployment, err := c.deployments.Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get deployment: %v", err)
	}
	route, err := c.route.Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get route: %v", err)
	}

	if err := c.handleVersion(ctx, authConfig, route, routerSecret, deployment, ingress, conditions); err != nil {
		return fmt.Errorf("error checking current version: %v", err)
	}

	return nil
}

func (c *authOperator) handleVersion(
	ctx context.Context,
	authConfig *configv1.Authentication,
	route *routev1.Route,
	routerSecret *corev1.Secret,
	deployment *appsv1.Deployment,
	ingress *configv1.Ingress,
	conditions *authConditions,
) error {
	// Checks readiness of all of:
	//    - route
	//    - well-known oauth endpoint
	//    - oauth clients
	//    - deployment
	// The ordering is important here as we want to become available after the
	// route + well-known + OAuth client checks AND one available OAuth server pod
	// but we do NOT want to go to the next version until all OAuth server pods are at that version

	routeReady, routeMsg, reason, err := c.checkRouteHealthy(route, routerSecret, ingress)
	conditions.handleDegradedWithReason("RouteHealth", err, reason)
	if err != nil {
		return fmt.Errorf("unable to check route health: %v", err)
	}
	if !routeReady {
		conditions.setProgressingTrueAndAvailableFalse("RouteNotReady", routeMsg)
		return nil
	}

	oauthClientsReady, oauthClientsMsg, err := c.oauthClientsReady(ctx)
	conditions.handleDegraded("OAuthClients", err)
	if err != nil {
		return fmt.Errorf("unable to check OAuth clients' readiness: %v", err)
	}
	if !oauthClientsReady {
		conditions.setProgressingTrueAndAvailableFalse("OAuthClientNotReady", oauthClientsMsg)
		return nil
	}

	// we have achieved our desired level
	conditions.setProgressingFalse()
	conditions.setAvailableTrue("AsExpected")
	c.setVersion("operator", operatorVersion)
	c.setVersion("oauth-openshift", oauthserverVersion)

	return nil
}

func (c *authOperator) checkRouteHealthy(route *routev1.Route, routerSecret *corev1.Secret, ingress *configv1.Ingress) (ready bool, msg, reason string, err error) {
	caData := routerSecretToCA(route, routerSecret, ingress)

	// if systemCABundle is not empty, append the new line to the caData
	if len(c.systemCABundle) > 0 {
		caData = append(bytes.TrimSpace(caData), []byte("\n")...)
	}

	rt, err := transport.TransportFor("", append(caData, c.systemCABundle...), nil, nil)
	if err != nil {
		return false, "", "FailedTransport", fmt.Errorf("failed to build transport for route: %v", err)
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+route.Spec.Host+"/healthz", nil)
	if err != nil {
		return false, "", "FailedRequest", fmt.Errorf("failed to build request to route: %v", err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return false, "", "FailedGet", fmt.Errorf("failed to GET route: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("route not yet available, /healthz returns '%s'", resp.Status), "", nil
	}

	return true, "", "", nil
}

func (c *authOperator) oauthClientsReady(ctx context.Context) (bool, string, error) {
	_, err := c.oauthClientClient.Get(ctx, "openshift-browser-client", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, "browser oauthclient does not exist", nil
		}
		return false, "", err
	}

	_, err = c.oauthClientClient.Get(ctx, "openshift-challenging-client", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, "challenging oauthclient does not exist", nil
		}
		return false, "", err
	}

	return true, "", nil
}

func (c *authOperator) setVersion(operandName, version string) {
	if c.versionGetter.GetVersions()[operandName] != version {
		c.versionGetter.SetVersion(operandName, version)
	}
}

func getPrefixFilter() controller.Filter {
	names := operator.FilterByNames("oauth-openshift")
	prefix := func(obj metav1.Object) bool { // TODO add helper to combine filters
		return names.Add(obj) || strings.HasPrefix(obj.GetName(), "v4-0-config-")
	}
	return controller.FilterFuncs{
		AddFunc: prefix,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return prefix(newObj)
		},
		DeleteFunc: prefix,
	}
}
