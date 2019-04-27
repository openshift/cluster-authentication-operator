package operator2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

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
	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/controller"
	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/operator"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var deploymentVersionHashKey = operatorv1.GroupName + "/rvs-hash"

const (
	clusterOperatorName     = "authentication"
	targetName              = "integrated-oauth-server"
	targetNamespace         = "openshift-authentication"
	targetNameOperator      = "authentication-operator"
	targetNamespaceOperator = "openshift-authentication-operator"
	globalConfigName        = "cluster"

	operatorSelfName       = "operator"
	oauthserverOperandName = "integrated-oauth-server"
	operatorVersionEnvName = "OPERATOR_IMAGE_VERSION"
	operandVersionEnvName  = "OPERAND_IMAGE_VERSION"
	operandImageEnvName    = "IMAGE"
	kasServicePortEnvName  = "KUBERNETES_SERVICE_PORT_HTTPS"

	machineConfigNamespace = "openshift-config-managed"
	userConfigNamespace    = "openshift-config"

	kasServiceAndEndpointName = "kubernetes"
	kasServiceFullName        = kasServiceAndEndpointName + "." + corev1.NamespaceDefault + ".svc"

	rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	systemConfigPath           = "/var/config/system"
	systemConfigPathConfigMaps = systemConfigPath + "/configmaps"
	systemConfigPathSecrets    = systemConfigPath + "/secrets"

	// if one day we ever need to come up with something else, we can still find the old secrets and config maps
	versionPrefix = "v4-0-"

	configVersionPrefix = versionPrefix + "config-"

	// secrets and config maps that we manually managed have this prefix
	systemConfigPrefix = configVersionPrefix + "system-"

	// secrets and config maps synced from openshift-config into our namespace have this prefix
	userConfigPrefix = configVersionPrefix + "user-"
	// idps that are synced have this prefix
	userConfigPrefixIDP = userConfigPrefix + "idp-"
	// templates that are synced have this prefix
	userConfigPrefixTemplate = userConfigPrefix + "template-"

	// secrets and config maps synced from openshift-config into our namespace have this path prefix
	userConfigPath = "/var/config/user"
	// root path for IDP data
	userConfigPathPrefixIDP = userConfigPath + "/" + "idp"
	// root path for template data
	userConfigPathPrefixTemplate = userConfigPath + "/" + "template"

	sessionNameAndKey = systemConfigPrefix + "session"
	sessionMount      = systemConfigPathSecrets + "/" + sessionNameAndKey
	sessionPath       = sessionMount + "/" + sessionNameAndKey

	serviceCABase  = "service-ca"
	serviceCAName  = systemConfigPrefix + serviceCABase
	serviceCAKey   = serviceCABase + ".crt"
	serviceCAMount = systemConfigPathConfigMaps + "/" + serviceCAName
	serviceCAPath  = serviceCAMount + "/" + serviceCAKey

	servingCertName     = systemConfigPrefix + "serving-cert"
	servingCertMount    = systemConfigPathSecrets + "/" + servingCertName
	servingCertPathCert = servingCertMount + "/" + corev1.TLSCertKey
	servingCertPathKey  = servingCertMount + "/" + corev1.TLSPrivateKeyKey

	cliConfigNameAndKey = systemConfigPrefix + "cliconfig"
	cliConfigMount      = systemConfigPathConfigMaps + "/" + cliConfigNameAndKey
	cliConfigPath       = cliConfigMount + "/" + cliConfigNameAndKey

	oauthMetadataName        = systemConfigPrefix + "metadata"
	oauthMetadataAPIEndpoint = "/.well-known/oauth-authorization-server"

	oauthBrowserClientName     = "openshift-browser-client"
	oauthChallengingClientName = "openshift-challenging-client"

	routerCertsSharedName = "router-certs"
	routerCertsLocalName  = systemConfigPrefix + routerCertsSharedName
	routerCertsLocalMount = systemConfigPathSecrets + "/" + routerCertsLocalName

	servicePort   = 443
	containerPort = 6443
)

// static environment variables from operator deployment
var (
	oauthserverImage   = os.Getenv(operandImageEnvName)
	oauthserverVersion = os.Getenv(operandVersionEnvName)

	operatorVersion = os.Getenv(operatorVersionEnvName)

	kasServicePort int
)

func init() {
	var err error
	kasServicePort, err = strconv.Atoi(os.Getenv(kasServicePortEnvName))
	if err != nil {
		panic(err)
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

	resourceSyncer resourcesynccontroller.ResourceSyncer
}

func NewAuthenticationOperator(
	authOpConfigClient OperatorClient,
	oauthClientClient oauthclient.OauthV1Interface,
	kubeInformersNamespaced informers.SharedInformerFactory,
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

		route: routeClient.Routes(targetNamespace),

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

		resourceSyncer: resourceSyncer,
	}

	coreInformers := kubeInformersNamespaced.Core().V1()
	configV1Informers := configInformers.Config().V1()

	targetNameFilter := operator.FilterByNames(targetName)
	configNameFilter := operator.FilterByNames(globalConfigName)
	prefixFilter := getPrefixFilter()

	return operator.New("AuthenticationOperator2", c,
		operator.WithInformer(routeInformer, targetNameFilter),
		operator.WithInformer(coreInformers.Services(), targetNameFilter),
		operator.WithInformer(kubeInformersNamespaced.Apps().V1().Deployments(), targetNameFilter),

		operator.WithInformer(coreInformers.Secrets(), prefixFilter),
		operator.WithInformer(coreInformers.ConfigMaps(), prefixFilter),

		operator.WithInformer(authOpConfigClient.Informers.Operator().V1().Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.Authentications(), configNameFilter),
		operator.WithInformer(configV1Informers.OAuths(), configNameFilter),
		operator.WithInformer(configV1Informers.Consoles(), configNameFilter, controller.WithNoSync()),
		operator.WithInformer(configV1Informers.Infrastructures(), configNameFilter, controller.WithNoSync()),
	)
}

func (c *authOperator) Key() (metav1.Object, error) {
	return c.authOperatorConfigClient.Client.Authentications().Get(globalConfigName, metav1.GetOptions{})
}

func (c *authOperator) Sync(obj metav1.Object) error {
	operatorConfig := obj.(*operatorv1.Authentication)

	// TODO bump and use IsOperatorManaged
	if operatorConfig.Spec.ManagementState != operatorv1.Managed {
		return nil // TODO do something better for all states
	}

	operatorConfigCopy := operatorConfig.DeepCopy()

	// clear degraded status
	setDegradedFalse(operatorConfigCopy)

	syncErr := c.handleSync(operatorConfigCopy)
	if syncErr != nil {
		setDegradedTrue(operatorConfigCopy, "OperatorSyncLoopError", syncErr.Error())
	}

	if _, _, err := v1helpers.UpdateStatus(c.authOperatorConfigClient, func(status *operatorv1.OperatorStatus) error {
		operatorConfigCopy.Status.OperatorStatus.DeepCopyInto(status)
		return nil
	}); err != nil {
		klog.Errorf("failed to update status: %v", err)
		if syncErr == nil {
			syncErr = err
		}
	}

	return syncErr
}

func (c *authOperator) handleSync(operatorConfig *operatorv1.Authentication) error {
	// resourceVersions serves to store versions of config resources so that we
	// can redeploy our payload should either change. We only omit the operator
	// config version, it would both cause redeploy loops (status updates cause
	// version change) and the relevant changes (logLevel, unsupportedConfigOverrides)
	// will cause a redeploy anyway
	// TODO move this hash from deployment meta to operatorConfig.status.generations.[...].hash
	resourceVersions := []string{}

	// The BLOCK sections are highly order dependent

	// ==================================
	// BLOCK 1: Metadata
	// ==================================

	route, routerSecret, err := c.handleRoute()
	if err != nil {
		return fmt.Errorf("failed handling the route: %v", err)
	}
	resourceVersions = append(resourceVersions, route.GetResourceVersion(), routerSecret.GetResourceVersion())

	// make sure API server sees our metadata as soon as we've got a route with a host
	metadata, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, getMetadataConfigMap(route))
	if err != nil {
		return fmt.Errorf("failure applying configMap for the .well-known endpoint: %v", err)
	}
	resourceVersions = append(resourceVersions, metadata.GetResourceVersion())

	authConfig, err := c.handleAuthConfig()
	if err != nil {
		return fmt.Errorf("failed handling authentication config: %v", err)
	}
	resourceVersions = append(resourceVersions, authConfig.GetResourceVersion())

	// ==================================
	// BLOCK 2: service and service-ca data
	// ==================================

	// make sure we create the service before we start asking about service certs
	service, _, err := resourceapply.ApplyService(c.services, c.recorder, defaultService())
	if err != nil {
		return fmt.Errorf("failed applying service object: %v", err)
	}
	resourceVersions = append(resourceVersions, service.GetResourceVersion())

	serviceCA, servingCert, err := c.handleServiceCA()
	if err != nil {
		return fmt.Errorf("failed handling service CA: %v", err)
	}
	resourceVersions = append(resourceVersions, serviceCA.GetResourceVersion(), servingCert.GetResourceVersion())

	// ==================================
	// BLOCK 3: build cli config
	// ==================================

	expectedSessionSecret, err := c.expectedSessionSecret()
	if err != nil {
		return fmt.Errorf("failed obtaining session secret: %v", err)
	}
	sessionSecret, _, err := resourceapply.ApplySecret(c.secrets, c.recorder, expectedSessionSecret)
	if err != nil {
		return fmt.Errorf("failed applying session secret: %v", err)
	}
	resourceVersions = append(resourceVersions, sessionSecret.GetResourceVersion())

	consoleConfig := c.handleConsoleConfig()
	resourceVersions = append(resourceVersions, consoleConfig.GetResourceVersion())

	infrastructureConfig := c.handleInfrastructureConfig()
	resourceVersions = append(resourceVersions, infrastructureConfig.GetResourceVersion())

	oauthConfig, expectedCLIconfig, syncData, err := c.handleOAuthConfig(operatorConfig, route, routerSecret, service, consoleConfig, infrastructureConfig)
	if err != nil {
		return fmt.Errorf("failed handling OAuth configuration: %v", err)
	}
	resourceVersions = append(resourceVersions, oauthConfig.GetResourceVersion())

	configResourceVersions, err := c.handleConfigSync(syncData)
	if err != nil {
		return fmt.Errorf("failed syncing configuration objects: %v", err)
	}
	resourceVersions = append(resourceVersions, configResourceVersions...)

	cliConfig, _, err := resourceapply.ApplyConfigMap(c.configMaps, c.recorder, expectedCLIconfig)
	if err != nil {
		return fmt.Errorf("failed applying configMap for the CLI configuration: %v", err)
	}
	resourceVersions = append(resourceVersions, cliConfig.GetResourceVersion())

	// ==================================
	// BLOCK 4: deployment
	// ==================================

	operatorDeployment, err := c.deployments.Deployments(targetNamespaceOperator).Get(targetNameOperator, metav1.GetOptions{})
	if err != nil {
		return err
	}
	resourceVersions = append(resourceVersions, operatorDeployment.GetResourceVersion())

	// deployment, have RV of all resources
	expectedDeployment := defaultDeployment(
		operatorConfig,
		syncData,
		routerSecret,
		operatorDeployment,
		resourceVersions...,
	)
	deployment, _, err := resourceapply.ApplyDeployment(
		c.deployments,
		c.recorder,
		expectedDeployment,
		resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorConfig.Status.Generations),
		operatorConfig.Generation != operatorConfig.Status.ObservedGeneration, // redeploy on operatorConfig.spec changes
	)
	if err != nil {
		return fmt.Errorf("failed applying deployment for the integrated OAuth server: %v", err)
	}

	// make sure we record the changes to the deployment
	resourcemerge.SetDeploymentGeneration(&operatorConfig.Status.Generations, deployment)
	operatorConfig.Status.ObservedGeneration = operatorConfig.Generation
	operatorConfig.Status.ReadyReplicas = deployment.Status.UpdatedReplicas

	klog.V(4).Infof("current deployment: %#v", deployment)

	if err := c.handleVersion(operatorConfig, authConfig, route, routerSecret, deployment); err != nil {
		return fmt.Errorf("error checking current version: %v", err)
	}

	return nil
}

func (c *authOperator) handleVersion(
	operatorConfig *operatorv1.Authentication,
	authConfig *configv1.Authentication,
	route *routev1.Route,
	routerSecret *corev1.Secret,
	deployment *appsv1.Deployment,
) error {
	// Checks readiness of all of:
	//    - route
	//    - well-known oauth endpoint
	//    - oauth clients
	//    - deployment
	// The ordering is important here as we want to become available after the
	// route + well-known + OAuth client checks AND one available OAuth server pod
	// but we do NOT want to go to the next version until all OAuth server pods are at that version

	routeReady, routeMsg, err := c.checkRouteHealthy(route, routerSecret)
	if err != nil {
		return fmt.Errorf("unable to check route health: %v", err)
	}
	if !routeReady {
		setProgressingTrueAndAvailableFalse(operatorConfig, "RouteNotReady", routeMsg)
		return nil
	}

	wellknownReady, wellknownMsg, err := c.checkWellknownEndpointsReady(authConfig, route)
	if err != nil {
		return fmt.Errorf("unable to check the .well-known endpoint: %v", err)
	}
	if !wellknownReady {
		setProgressingTrueAndAvailableFalse(operatorConfig, "WellKnownNotReady", wellknownMsg)
		return nil
	}

	oauthClientsReady, oauthClientsMsg, err := c.oauthClientsReady(route)
	if err != nil {
		return fmt.Errorf("unable to check OAuth clients' readiness: %v", err)
	}
	if !oauthClientsReady {
		setProgressingTrueAndAvailableFalse(operatorConfig, "OAuthClientNotReady", oauthClientsMsg)
		return nil
	}

	if deploymentReady := c.checkDeploymentReady(deployment, operatorConfig); !deploymentReady {
		return nil
	}

	// we have achieved our desired level
	setProgressingFalse(operatorConfig)
	setAvailableTrue(operatorConfig, "AsExpected")
	c.setVersion(operatorSelfName, operatorVersion)
	c.setVersion(oauthserverOperandName, oauthserverVersion)

	return nil
}

func (c *authOperator) checkDeploymentReady(deployment *appsv1.Deployment, operatorConfig *operatorv1.Authentication) bool {
	reason := "OAuthServerDeploymentNotReady"

	if deployment.DeletionTimestamp != nil {
		setProgressingTrueAndAvailableFalse(operatorConfig, reason, "deployment is being deleted")
		return false
	}

	if deployment.Status.AvailableReplicas > 0 && deployment.Status.UpdatedReplicas != deployment.Status.Replicas {
		setProgressingTrue(operatorConfig, reason, "not all deployment replicas are ready")
		setAvailableTrue(operatorConfig, "OAuthServerDeploymentHasAvailableReplica")
		return false
	}

	if deployment.Generation != deployment.Status.ObservedGeneration {
		setProgressingTrue(operatorConfig, reason, "deployment's observed generation did not reach the expected generation")
		return false
	}

	if deployment.Status.UpdatedReplicas != deployment.Status.Replicas || deployment.Status.UnavailableReplicas > 0 {
		setProgressingTrue(operatorConfig, reason, "not all deployment replicas are ready")
		return false
	}

	return true
}

func (c *authOperator) checkRouteHealthy(route *routev1.Route, routerSecret *corev1.Secret) (bool, string, error) {
	caData := routerSecretToCA(route, routerSecret)

	rt, err := transportFor("", caData, nil, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to build transport for route: %v", err)
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+route.Spec.Host+"/healthz", nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to build request to route: %v", err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return false, "", fmt.Errorf("failed to GET route: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("route not yet available, /healthz returns '%s'", resp.Status), nil
	}

	return true, "", nil
}

func (c *authOperator) checkWellknownEndpointsReady(authConfig *configv1.Authentication, route *routev1.Route) (bool, string, error) {
	// TODO: don't perform this check when OAuthMetadata reference is set up,
	// the code in configmap.go does not handle such cases yet
	if len(authConfig.Spec.OAuthMetadata.Name) != 0 || authConfig.Spec.Type != configv1.AuthenticationTypeIntegratedOAuth {
		return true, "", nil
	}

	caData, err := ioutil.ReadFile(rootCAFile)
	if err != nil {
		return false, "", fmt.Errorf("failed to read SA ca.crt: %v", err)
	}

	// pass the KAS service name for SNI
	rt, err := transportFor(kasServiceFullName, caData, nil, nil)
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

func (c *authOperator) getAPIServerIPs() ([]string, error) {
	kasService, err := c.services.Services(corev1.NamespaceDefault).Get(kasServiceAndEndpointName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kube api server service: %v", err)
	}

	targetPort, ok := getKASTargetPortFromService(kasService)
	if !ok {
		return nil, fmt.Errorf("unable to find kube api server service target port: %#v", kasService)
	}

	kasEndpoint, err := c.endpoints.Endpoints(corev1.NamespaceDefault).Get(kasServiceAndEndpointName, metav1.GetOptions{})
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
			ips = append(ips, fmt.Sprintf("%s:%d", address.IP, targetPort))
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

func (c *authOperator) checkWellknownEndpointReady(apiIP string, rt http.RoundTripper, route *routev1.Route) (bool, string, error) {
	wellKnown := "https://" + apiIP + oauthMetadataAPIEndpoint

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

	expectedMetadata := getMetadataStruct(route)
	if !reflect.DeepEqual(expectedMetadata, receivedValues) {
		return false, fmt.Sprintf("the value returned by the well-known %s endpoint does not match expectations", wellKnown), nil
	}

	return true, "", nil
}

func (c *authOperator) oauthClientsReady(route *routev1.Route) (bool, string, error) {
	_, err := c.oauthClientClient.Get(oauthBrowserClientName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, "browser oauthclient does not exist", nil
		}
		return false, "", err
	}

	_, err = c.oauthClientClient.Get(oauthChallengingClientName, metav1.GetOptions{})
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

func defaultLabels() map[string]string {
	return map[string]string{
		"app": targetName,
	}
}

func defaultMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:            targetName,
		Namespace:       targetNamespace,
		Labels:          defaultLabels(),
		Annotations:     map[string]string{},
		OwnerReferences: nil, // TODO
	}
}

func defaultGlobalConfigMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:   globalConfigName,
		Labels: map[string]string{},
		Annotations: map[string]string{
			"release.openshift.io/create-only": "true",
		},
	}
}

func getPrefixFilter() controller.Filter {
	names := operator.FilterByNames(targetName)
	prefix := func(obj metav1.Object) bool { // TODO add helper to combine filters
		return names.Add(obj) || strings.HasPrefix(obj.GetName(), configVersionPrefix)
	}
	return controller.FilterFuncs{
		AddFunc: prefix,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return prefix(newObj)
		},
		DeleteFunc: prefix,
	}
}
