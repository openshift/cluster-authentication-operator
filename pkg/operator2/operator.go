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
	"github.com/openshift/cluster-authentication-operator/pkg/transport"
	"github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	deploymentVersionHashKey = "operator.openshift.io/rvs-hash"
)

// static environment variables from operator deployment
var (
	oauthserverImage   = os.Getenv("IMAGE")
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

	services                corev1client.ServicesGetter
	endpoints               corev1client.EndpointsGetter
	secrets                 corev1client.SecretsGetter
	configMaps              corev1client.ConfigMapsGetter
	deployments             appsv1client.DeploymentsGetter
	bootstrapUserDataGetter bootstrapauthenticator.BootstrapUserDataGetter

	authentication configv1client.AuthenticationInterface
	oauth          configv1client.OAuthInterface
	console        configv1client.ConsoleInterface
	infrastructure configv1client.InfrastructureInterface
	ingress        configv1client.IngressInterface
	apiserver      configv1client.APIServerInterface
	proxy          configv1client.ProxyInterface

	systemCABundle []byte

	bootstrapUserChangeRollOut bool

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

	namespacesGetter := kubeClient.CoreV1()
	c.bootstrapUserDataGetter = bootstrapauthenticator.NewBootstrapUserDataGetter(c.secrets, namespacesGetter)
	if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		c.bootstrapUserChangeRollOut = true
	} else {
		c.bootstrapUserChangeRollOut = userExists
	}

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

func (c *authOperator) handleSync(ctx context.Context, operatorConfig *operatorv1.Authentication, conditions *authConditions) error {
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
	//
	// TODO: Remove this when we break the order dependent code
	_, operatorStatus, _, err := c.authOperatorConfigClient.GetOperatorState()
	if err != nil {
		return err
	}
	metadataCondition := v1helpers.FindOperatorCondition(operatorStatus.Conditions, "AuthMetadataProgressing")
	if metadataCondition == nil {
		return fmt.Errorf("metadata progressing condition not found")
	}
	if metadataCondition.Status == operatorv1.ConditionTrue {
		return fmt.Errorf("operator is waiting for metadata")
	}

	// ==================================
	// BLOCK 2: service and service-ca data
	// ==================================
	//
	// TODO: Remove this when we break the order dependent code
	serviceCaCondition := v1helpers.FindOperatorCondition(operatorStatus.Conditions, "AuthServiceCAProgressing")
	if serviceCaCondition == nil {
		return fmt.Errorf("service ca progressing condition not found")
	}
	if serviceCaCondition.Status == operatorv1.ConditionTrue {
		return fmt.Errorf("operator is waiting for service CA")
	}

	// ==================================
	// BLOCK 3: build cli config
	// ==================================

	cliConfigCondition := v1helpers.FindOperatorCondition(operatorStatus.Conditions, "AuthCLIConfigProgressing")
	if cliConfigCondition == nil {
		return fmt.Errorf("CLI config progressing condition not found")
	}
	if cliConfigCondition.Status == operatorv1.ConditionTrue {
		return fmt.Errorf("operator is waiting for CLI config")
	}

	// ==================================
	// BLOCK 4: deployment
	// ==================================
	route, err := c.route.Get(ctx, "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return err
	}

	if err := c.ensureBootstrappedOAuthClients(ctx, "https://"+route.Spec.Host); err != nil {
		return err
	}

	proxyConfig := c.handleProxyConfig(ctx)
	resourceVersions = append(resourceVersions, "proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion)

	configResourceVersions, err := c.handleConfigResourceVersions(ctx)
	if err != nil {
		return err
	}
	resourceVersions = append(resourceVersions, configResourceVersions...)

	// Determine whether the bootstrap user has been deleted so that
	// detail can be used in computing the deployment.
	if c.bootstrapUserChangeRollOut {
		if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
			klog.Warningf("Unable to determine the state of bootstrap user: %v", err)
		} else {
			c.bootstrapUserChangeRollOut = userExists
		}
	}

	// deployment, have RV of all resources
	expectedDeployment, err := defaultDeployment(
		operatorConfig,
		proxyConfig,
		c.bootstrapUserChangeRollOut,
		resourceVersions...,
	)
	if err != nil {
		return fmt.Errorf("failed to determine the shape of the expected deployment: %v", err)
	}

	deployment, _, err := resourceapply.ApplyDeployment(
		c.deployments,
		c.recorder,
		expectedDeployment,
		resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorConfig.Status.Generations),
	)
	if err != nil {
		return fmt.Errorf("failed applying deployment for the integrated OAuth server: %v", err)
	}

	// make sure we record the changes to the deployment
	resourcemerge.SetDeploymentGeneration(&operatorConfig.Status.Generations, deployment)
	operatorConfig.Status.ObservedGeneration = operatorConfig.Generation
	operatorConfig.Status.ReadyReplicas = deployment.Status.UpdatedReplicas

	klog.V(4).Infof("current deployment: %#v", deployment)

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

	if err := c.handleVersion(ctx, operatorConfig, authConfig, route, routerSecret, deployment, ingress, conditions); err != nil {
		return fmt.Errorf("error checking current version: %v", err)
	}

	return nil
}

func (c *authOperator) handleVersion(
	ctx context.Context,
	operatorConfig *operatorv1.Authentication,
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

	if deploymentReady := c.checkDeploymentReady(deployment, conditions); !deploymentReady {
		return nil
	}

	// we have achieved our desired level
	conditions.setProgressingFalse()
	conditions.setAvailableTrue("AsExpected")
	c.setVersion("operator", operatorVersion)
	c.setVersion("oauth-openshift", oauthserverVersion)

	return nil
}

func (c *authOperator) checkDeploymentReady(deployment *appsv1.Deployment, conditions *authConditions) bool {
	reason := "OAuthServerDeploymentNotReady"

	if deployment.DeletionTimestamp != nil {
		conditions.setProgressingTrueAndAvailableFalse(reason, "deployment is being deleted")
		return false
	}

	if deployment.Status.AvailableReplicas > 0 && deployment.Status.UpdatedReplicas != deployment.Status.Replicas {
		conditions.setProgressingTrue(reason, "not all deployment replicas are ready")
		conditions.setAvailableTrue("OAuthServerDeploymentHasAvailableReplica")
		return false
	}

	if deployment.Generation != deployment.Status.ObservedGeneration {
		conditions.setProgressingTrue(reason, "deployment's observed generation did not reach the expected generation")
		return false
	}

	if deployment.Status.UpdatedReplicas != deployment.Status.Replicas || deployment.Status.UnavailableReplicas > 0 {
		conditions.setProgressingTrue(reason, "not all deployment replicas are ready")
		return false
	}

	return true
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

// TODO: Remove this as there is duplicate in controllers/metadata.
func getOAuthMetadata(host string) string {
	stubMetadata := `
{
  "issuer": "https://%s",
  "authorization_endpoint": "https://%s/oauth/authorize",
  "token_endpoint": "https://%s/oauth/token",
  "scopes_supported": [
    "user:check-access",
    "user:full",
    "user:info",
    "user:list-projects",
    "user:list-scoped-projects"
  ],
  "response_types_supported": [
    "code",
    "token"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit"
  ],
  "code_challenge_methods_supported": [
    "plain",
    "S256"
  ]
}
`
	return strings.TrimSpace(fmt.Sprintf(stubMetadata, host, host, host))
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
