package operator

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	certapiv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	certinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
	utilpointer "k8s.io/utils/pointer"
	kubemigratorclient "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/clientset"
	migrationv1alpha1informer "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/informer"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformers "github.com/openshift/client-go/oauth/informers/externalversions"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	workloadcontroller "github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	apiservercontrollerset "github.com/openshift/library-go/pkg/operator/apiserver/controllerset"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/csr"
	"github.com/openshift/library-go/pkg/operator/encryption"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/managementstatecontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/revisioncontroller"
	"github.com/openshift/library-go/pkg/operator/staleconditions"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/guard"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/revision"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/configobservercontroller"
	componentroutesecretsync "github.com/openshift/cluster-authentication-operator/pkg/controllers/customroute"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/deployment"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/ingressnodesavailable"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/ingressstate"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/metadata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/oauthclientscontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/oauthendpoints"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/payload"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/proxyconfig"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/readiness"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/routercerts"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/serviceca"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/trustdistribution"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/webhookauthenticator"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/assets"
	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/configobservercontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/revisionclient"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/workload"
)

const (
	resync = 20 * time.Minute
)

// operatorContext holds combined data for both operators
type operatorContext struct {
	kubeClient     kubernetes.Interface
	configClient   configclient.Interface
	operatorClient *OperatorClient

	versionRecorder status.VersionGetter

	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces
	operatorConfigInformer     configinformer.SharedInformerFactory
	operatorInformer           operatorinformer.SharedInformerFactory

	resourceSyncController *resourcesynccontroller.ResourceSyncController

	informersToRunFunc   []func(stopCh <-chan struct{})
	controllersToRunFunc []func(ctx context.Context, workers int)
}

// RunOperator prepares and runs both operators OAuth and OAuthAPIServer
// TODO: in the future we might move each operator to its onw pkg
// TODO: consider using the new operator framework
func RunOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	configClient, err := configclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

	authOperatorClient, err := operatorclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		"default",
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
		"openshift-oauth-apiserver",
		"openshift-authentication-operator",
		"", // an informer for non-namespaced resources
		"kube-system",
		libgoetcd.EtcdEndpointNamespace,
	)

	// short resync period as this drives the check frequency when checking the .well-known endpoint. 20 min is too slow for that.
	operatorConfigInformers := operatorinformer.NewSharedInformerFactory(authOperatorClient, time.Second*30)

	operatorClient := &OperatorClient{
		operatorConfigInformers,
		authOperatorClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		controllerContext.EventRecorder,
	)

	versionRecorder := status.NewVersionGetter()
	clusterOperator, err := configClient.ConfigV1().ClusterOperators().Get(ctx, "authentication", metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	// perform version changes to the version getter prior to tying it up in the status controller
	// via change-notification channel so that it only updates operator version in status once
	// either of the workloads synces
	for _, version := range clusterOperator.Status.Versions {
		versionRecorder.SetVersion(version.Name, version.Version)
	}
	versionRecorder.SetVersion("operator", os.Getenv("OPERATOR_IMAGE_VERSION"))

	operatorCtx := &operatorContext{}
	operatorCtx.versionRecorder = versionRecorder
	operatorCtx.kubeClient = kubeClient
	operatorCtx.configClient = configClient
	operatorCtx.kubeInformersForNamespaces = kubeInformersForNamespaces
	operatorCtx.resourceSyncController = resourceSyncer
	operatorCtx.operatorClient = operatorClient
	operatorCtx.operatorInformer = operatorConfigInformers
	operatorCtx.operatorConfigInformer = configinformer.NewSharedInformerFactoryWithOptions(configClient, resync)

	if err := prepareOauthOperator(controllerContext, operatorCtx); err != nil {
		return err
	}
	if err := prepareOauthAPIServerOperator(ctx, controllerContext, operatorCtx); err != nil {
		return err
	}

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(operatorCtx.operatorClient, controllerContext.EventRecorder)
	logLevelController := loglevel.NewClusterOperatorLoggingController(operatorCtx.operatorClient, controllerContext.EventRecorder)

	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc,
		kubeInformersForNamespaces.Start,
		operatorConfigInformers.Start,
		operatorCtx.operatorConfigInformer.Start,
	)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, resourceSyncer.Run, configOverridesController.Run, logLevelController.Run)

	for _, informerToRunFn := range operatorCtx.informersToRunFunc {
		informerToRunFn(ctx.Done())
	}
	for _, controllerRunFn := range operatorCtx.controllersToRunFunc {
		go controllerRunFn(ctx, 1)
	}

	<-ctx.Done()
	return nil
}

func prepareOauthOperator(controllerContext *controllercmd.ControllerContext, operatorCtx *operatorContext) error {
	routeClient, err := routeclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	// protobuf can be used with non custom resources
	oauthClient, err := oauthclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	openshiftAuthenticationInformers := operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication")
	kubeSystemNamespaceInformers := operatorCtx.kubeInformersForNamespaces.InformersFor("kube-system")

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace("openshift-authentication"),
		routeinformer.WithTweakListOptions(singleNameListOptions("oauth-openshift")),
	)

	oauthInformers := oauthinformers.NewSharedInformerFactory(oauthClient, resync)

	// add syncing for the OAuth metadata ConfigMap
	if err := operatorCtx.resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "oauth-openshift"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-metadata"},
	); err != nil {
		return err
	}

	staleConditions := staleconditions.NewRemoveStaleConditionsController(
		[]string{
			// condition types removed in 4.8
			"OAuthRouteCheckEndpointAccessibleControllerDegraded",
			"OAuthRouteCheckEndpointAccessibleControllerAvailable",
			"OAuthServiceCheckEndpointAccessibleControllerDegraded",
			"OAuthServiceCheckEndpointAccessibleControllerAvailable",
			"OAuthServiceEndpointsCheckEndpointAccessibleControllerDegraded",
			"OAuthServiceEndpointsCheckEndpointAccessibleControllerAvailable",
			"OAuthServerIngressConfigDegraded",
			"OAuthServerProxyDegraded",
			"OAuthServerRouteDegraded",
			"OAuthVersionDeploymentAvailable",
			"OAuthVersionDeploymentProgressing",
			"OAuthVersionDeploymentDegraded",
			"OAuthVersionRouteDegraded",
			"OAuthVersionRouteProgressing",
			"OAuthVersionRouteAvailable",
			"OAuthVersionRouteSecretDegraded",
			"OAuthVersionIngressConfigDegraded",
		},
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	staticResourceController := staticresourcecontroller.NewStaticResourceController(
		"OpenshiftAuthenticationStaticResources",
		assets.Asset,
		[]string{
			"oauth-openshift/audit-policy.yaml",
			"oauth-openshift/ns.yaml",
			"oauth-openshift/authentication-clusterrolebinding.yaml",
			"oauth-openshift/cabundle.yaml",
			"oauth-openshift/branding-secret.yaml",
			"oauth-openshift/serviceaccount.yaml",
			"oauth-openshift/oauth-service.yaml",
			"oauth-openshift/trust_distribution_role.yaml",
			"oauth-openshift/trust_distribution_rolebinding.yaml",
		},
		resourceapply.NewKubeClientHolder(operatorCtx.kubeClient),
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	).AddKubeInformers(operatorCtx.kubeInformersForNamespaces)

	configObserver := configobservercontroller.NewConfigObserver(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorConfigInformer,
		operatorCtx.resourceSyncController,
		controllerContext.EventRecorder,
	)

	routerCertsController := routercerts.NewRouterCertsDomainValidationController(
		operatorCtx.operatorClient,
		operatorCtx.kubeClient.CoreV1(),
		controllerContext.EventRecorder,
		operatorCtx.operatorConfigInformer.Config().V1().Ingresses(),
		openshiftAuthenticationInformers.Core().V1().Secrets(),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets(),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().ConfigMaps(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"v4-0-config-system-custom-router-certs",
		"oauth-openshift",
	)

	ingressStateController := ingressstate.NewIngressStateController(
		openshiftAuthenticationInformers,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.operatorClient,
		"openshift-authentication",
		controllerContext.EventRecorder)

	wellKnownReadyController := readiness.NewWellKnownReadyController(
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorConfigInformer,
		routeInformersNamespaced.Route().V1().Routes(),
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	metadataController := metadata.NewMetadataController(
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		operatorCtx.operatorConfigInformer,
		routeInformersNamespaced,
		operatorCtx.kubeClient.CoreV1(),
		routeClient.RouteV1().Routes("openshift-authentication"),
		operatorCtx.configClient.ConfigV1().Authentications(),
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	serviceCAController := serviceca.NewServiceCAController(
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		operatorCtx.operatorConfigInformer,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	payloadConfigController := payload.NewPayloadConfigController(
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.operatorClient,
		operatorCtx.operatorClient.Client,
		routeInformersNamespaced.Route().V1().Routes(),
		controllerContext.EventRecorder,
	)

	oauthClientsController := oauthclientscontroller.NewOAuthClientsController(
		operatorCtx.operatorClient,
		oauthClient.OauthV1().OAuthClients(),
		oauthInformers,
		routeInformersNamespaced,
		operatorCtx.operatorConfigInformer,
		controllerContext.EventRecorder,
	)

	deploymentController := deployment.NewOAuthServerWorkloadController(
		operatorCtx.operatorClient,
		workloadcontroller.CountNodesFuncWrapper(operatorCtx.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes().Lister()),
		workloadcontroller.EnsureAtMostOnePodPerNode,
		operatorCtx.kubeClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes(),
		operatorCtx.configClient.ConfigV1().ClusterOperators(),
		operatorCtx.operatorConfigInformer,
		routeInformersNamespaced,
		operatorCtx.operatorClient.Client,
		bootstrapauthenticator.NewBootstrapUserDataGetter(operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeClient.CoreV1()),
		controllerContext.EventRecorder,
		operatorCtx.versionRecorder,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
	)

	workersAvailableController := ingressnodesavailable.NewIngressNodesAvailableController(
		operatorCtx.operatorClient,
		operatorCtx.operatorInformer.Operator().V1().IngressControllers(),
		controllerContext.EventRecorder,
		operatorCtx.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes(),
	)

	systemCABundle, err := loadSystemCACertBundle()
	if err != nil {
		return err
	}

	authRouteCheckController := oauthendpoints.NewOAuthRouteCheckController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-config-managed"),
		routeInformersNamespaced.Route().V1().Routes(),
		operatorCtx.operatorConfigInformer.Config().V1().Ingresses(),
		systemCABundle,
		controllerContext.EventRecorder,
	)

	authServiceCheckController := oauthendpoints.NewOAuthServiceCheckController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		controllerContext.EventRecorder,
	)

	authServiceEndpointCheckController := oauthendpoints.NewOAuthServiceEndpointsCheckController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		controllerContext.EventRecorder,
	)

	proxyConfigController := proxyconfig.NewProxyConfigChecker(
		routeInformersNamespaced.Route().V1().Routes(),
		operatorCtx.kubeInformersForNamespaces,
		"openshift-authentication",
		"oauth-openshift",
		map[string][]string{
			"openshift-authentication-operator": {"trusted-ca-bundle"},
			"openshift-config-managed":          {"default-ingress-cert"},
		},
		controllerContext.EventRecorder,
		operatorCtx.operatorClient,
	)

	customRouteController := componentroutesecretsync.NewCustomRouteController(
		componentroutesecretsync.OAuthComponentRouteNamespace,
		componentroutesecretsync.OAuthComponentRouteName,
		"openshift-authentication",
		"v4-0-config-system-custom-router-certs",
		operatorCtx.operatorConfigInformer.Config().V1().Ingresses(),
		operatorCtx.configClient.ConfigV1().Ingresses(),
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1().Routes("openshift-authentication"),
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
		operatorCtx.resourceSyncController,
	)

	// TODO remove this controller once we support Removed
	managementStateController := managementstatecontroller.NewOperatorManagementStateController("authentication", operatorCtx.operatorClient, controllerContext.EventRecorder)
	management.SetOperatorNotRemovable()

	trustDistributionController := trustdistribution.NewTrustDistributionController(
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorConfigInformer.Config().V1().Ingresses(),
		controllerContext.EventRecorder,
	)

	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc,
		oauthInformers.Start,
		routeInformersNamespaced.Start,
		kubeSystemNamespaceInformers.Start,
		openshiftAuthenticationInformers.Start,
	)

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc,
		configObserver.Run,
		deploymentController.Run,
		managementStateController.Run,
		metadataController.Run,
		oauthClientsController.Run,
		payloadConfigController.Run,
		routerCertsController.Run,
		serviceCAController.Run,
		staticResourceController.Run,
		wellKnownReadyController.Run,
		authRouteCheckController.Run,
		authServiceCheckController.Run,
		authServiceEndpointCheckController.Run,
		workersAvailableController.Run,
		proxyConfigController.Run,
		customRouteController.Run,
		trustDistributionController.Run,
		func(ctx context.Context, workers int) { staleConditions.Run(ctx, workers) },
		func(ctx context.Context, workers int) { ingressStateController.Run(ctx, workers) },
	)

	return nil
}

func prepareOauthAPIServerOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext, operatorCtx *operatorContext) error {
	eventRecorder := controllerContext.EventRecorder.ForComponent("oauth-apiserver")

	// add syncing for etcd certs for oauthapi-server
	if err := operatorCtx.resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-oauth-apiserver", Name: "etcd-serving-ca"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "etcd-serving-ca"},
	); err != nil {
		return err
	}
	if err := operatorCtx.resourceSyncController.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-oauth-apiserver", Name: "etcd-client"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "etcd-client"},
	); err != nil {
		return err
	}

	apiregistrationv1Client, err := apiregistrationclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	apiregistrationInformers := apiregistrationinformers.NewSharedInformerFactory(apiregistrationv1Client, 10*time.Minute)

	kubeInformers := certinformers.NewSharedInformerFactory(operatorCtx.kubeClient, resync)

	nodeProvider := encryptiondeployer.NewDeploymentNodeProvider("openshift-oauth-apiserver", operatorCtx.kubeInformersForNamespaces)
	deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer("revision", "openshift-oauth-apiserver", operatorCtx.kubeInformersForNamespaces, operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeClient.CoreV1(), nodeProvider)
	if err != nil {
		return err
	}
	migrationClient := kubemigratorclient.NewForConfigOrDie(controllerContext.KubeConfig)
	migrationInformer := migrationv1alpha1informer.NewSharedInformerFactory(migrationClient, time.Minute*30)
	migrator := migrators.NewKubeStorageVersionMigrator(migrationClient, migrationInformer.Migration().V1alpha1(), operatorCtx.kubeClient.Discovery())

	authAPIServerWorkload := workload.NewOAuthAPIServerWorkload(
		operatorCtx.operatorClient.Client,
		workloadcontroller.CountNodesFuncWrapper(operatorCtx.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes().Lister()),
		workloadcontroller.EnsureAtMostOnePodPerNode,
		"openshift-oauth-apiserver",
		os.Getenv("IMAGE_OAUTH_APISERVER"),
		os.Getenv("OPERATOR_IMAGE"),
		operatorCtx.kubeClient,
		operatorCtx.versionRecorder)

	infra, err := operatorCtx.configClient.ConfigV1().Infrastructures().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		klog.Warningf("unexpectedly no infrastructure resource found, assuming non SingleReplicaTopologyMode controlPlaneTopology: %v", err)
	} else if err != nil {
		return err
	}
	var statusControllerOptions []func(*status.StatusSyncer) *status.StatusSyncer
	if infra == nil || infra.Status.ControlPlaneTopology != configv1.SingleReplicaTopologyMode {
		statusControllerOptions = append(statusControllerOptions, apiservercontrollerset.WithStatusControllerPdbCompatibleHighInertia("(APIServer|OAuthServer)"))
	}

	const apiServerConditionsPrefix = "APIServer"

	apiServerControllers, err := apiservercontrollerset.NewAPIServerControllerSet(
		operatorCtx.operatorClient,
		eventRecorder,
	).WithWorkloadController(
		"OAuthAPIServerController",
		"openshift-authentication-operator",
		"openshift-oauth-apiserver",
		os.Getenv("OPERATOR_IMAGE_VERSION"),
		"oauth",
		apiServerConditionsPrefix,
		operatorCtx.kubeClient,
		authAPIServerWorkload,
		operatorCtx.configClient.ConfigV1().ClusterOperators(),
		operatorCtx.versionRecorder,
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorClient.Informers.Operator().V1().Authentications().Informer(),
	).WithStaticResourcesController(
		"APIServerStaticResources",
		assets.Asset,
		[]apiservercontrollerset.ConditionalFiles{
			{
				Files: []string{
					"oauth-apiserver/ns.yaml",
					"oauth-apiserver/apiserver-clusterrolebinding.yaml",
					"oauth-apiserver/svc.yaml",
					"oauth-apiserver/sa.yaml",
					"oauth-apiserver/RBAC/useroauthaccesstokens_binding.yaml",
					"oauth-apiserver/RBAC/useroauthaccesstokens_clusterrole.yaml",
				},
			},
			{
				Files: []string{
					"oauth-apiserver/oauth-apiserver-pdb.yaml",
				},
				ShouldCreateFn: func() bool {
					isSNO, precheckSucceeded, err := guard.IsSNOCheckFnc(operatorCtx.operatorConfigInformer.Config().V1().Infrastructures())()
					if err != nil {
						klog.Errorf("IsSNOCheckFnc failed: %v", err)
						return false
					}
					if !precheckSucceeded {
						klog.V(4).Infof("IsSNOCheckFnc precheck did not succeed, skipping")
						return false
					}
					return !isSNO
				},
				ShouldDeleteFn: func() bool {
					isSNO, precheckSucceeded, err := guard.IsSNOCheckFnc(operatorCtx.operatorConfigInformer.Config().V1().Infrastructures())()
					if err != nil {
						klog.Errorf("IsSNOCheckFnc failed: %v", err)
						return false
					}
					if !precheckSucceeded {
						klog.V(4).Infof("IsSNOCheckFnc precheck did not succeed, skipping")
						return false
					}
					return isSNO
				},
			},
		},

		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.kubeClient,
	).WithRevisionController(
		"openshift-oauth-apiserver",
		[]revisioncontroller.RevisionResource{{
			Name: "audit", // defined in library-go
		}},
		[]revision.RevisionResource{{
			Name:     "encryption-config",
			Optional: true,
		}},
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		revisionclient.New(operatorCtx.operatorClient, operatorCtx.operatorClient.Client),
		v1helpers.CachedConfigMapGetter(operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeInformersForNamespaces),
		v1helpers.CachedSecretGetter(operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeInformersForNamespaces),
	).WithAPIServiceController(
		"openshift-apiserver",
		func() ([]*apiregistrationv1.APIService, error) { return apiServices(), nil },
		apiregistrationInformers,
		apiregistrationv1Client.ApiregistrationV1(),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		operatorCtx.kubeClient,
	).WithEncryptionControllers(
		"openshift-oauth-apiserver",
		encryption.StaticEncryptionProvider{
			schema.GroupResource{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
			schema.GroupResource{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
		},
		deployer,
		migrator,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.configClient.ConfigV1().APIServers(),
		operatorCtx.operatorConfigInformer.Config().V1().APIServers(),
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.resourceSyncController,
	).WithUnsupportedConfigPrefixForEncryptionControllers(
		oauthapiconfigobservercontroller.OAuthAPIServerConfigPrefix,
	).WithFinalizerController(
		"openshift-oauth-apiserver",
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		operatorCtx.kubeClient.CoreV1(),
	).WithSecretRevisionPruneController(
		"openshift-oauth-apiserver",
		[]string{"encryption-config-"},
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeInformersForNamespaces,
	).WithAuditPolicyController(
		"openshift-oauth-apiserver",
		"audit",
		operatorCtx.operatorConfigInformer.Config().V1().APIServers().Lister(),
		operatorCtx.operatorConfigInformer,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		operatorCtx.kubeClient,
	).
		WithClusterOperatorStatusController(
			"authentication",
			[]configv1.ObjectReference{
				{Group: operatorv1.GroupName, Resource: "authentications", Name: "cluster"},
				{Group: configv1.GroupName, Resource: "authentications", Name: "cluster"},
				{Group: configv1.GroupName, Resource: "infrastructures", Name: "cluster"},
				{Group: configv1.GroupName, Resource: "oauths", Name: "cluster"},
				{Group: routev1.GroupName, Resource: "routes", Name: "oauth-openshift", Namespace: "openshift-authentication"},
				{Resource: "services", Name: "oauth-openshift", Namespace: "openshift-authentication"},
				{Resource: "namespaces", Name: "openshift-config"},
				{Resource: "namespaces", Name: "openshift-config-managed"},
				{Resource: "namespaces", Name: "openshift-authentication"},
				{Resource: "namespaces", Name: "openshift-authentication-operator"},
				{Resource: "namespaces", Name: "openshift-ingress"},
				{Resource: "namespaces", Name: "openshift-oauth-apiserver"},
			},
			operatorCtx.configClient.ConfigV1(),
			operatorCtx.operatorConfigInformer.Config().V1().ClusterOperators(),
			operatorCtx.versionRecorder,
			statusControllerOptions...,
		).
		WithoutLogLevelController().
		WithoutConfigUpgradableController().
		PrepareRun()

	if err != nil {
		return err
	}

	configObserver := oauthapiconfigobservercontroller.NewConfigObserverController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorConfigInformer,
		operatorCtx.resourceSyncController,
		controllerContext.EventRecorder,
	)

	webhookAuthController := webhookauthenticator.NewWebhookAuthenticatorController(
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication-operator"),
		operatorCtx.operatorConfigInformer,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.configClient.ConfigV1().Authentications(),
		operatorCtx.operatorClient.Client,
		operatorCtx.operatorClient,
		operatorCtx.versionRecorder,
		eventRecorder,
	)

	authenticatorCertRequester, err := csr.NewClientCertificateController(
		csr.ClientCertOption{
			SecretNamespace: "openshift-oauth-apiserver",
			SecretName:      "openshift-authenticator-certs",
		},
		csr.CSROption{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "system:openshift:openshift-authenticator-",
				Labels:       map[string]string{"authentication.openshift.io/csr": "openshift-authenticator"},
			},
			Subject:    &pkix.Name{CommonName: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
			SignerName: certapiv1.KubeAPIServerClientSignerName,
		},
		kubeInformers.Certificates().V1().CertificateSigningRequests(),
		operatorCtx.kubeClient.CertificatesV1().CertificateSigningRequests(),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Secrets(),
		operatorCtx.kubeClient.CoreV1(),
		eventRecorder,
		"OpenShiftAuthenticatorCertRequester",
	)
	if err != nil {
		return err
	}

	labelsReq, err := labels.NewRequirement("authentication.openshift.io/csr", selection.Equals, []string{"openshift-authenticator"})
	if err != nil {
		return err
	}
	labelSelector := labels.NewSelector().Add(*labelsReq)

	webhookCertsApprover := csr.NewCSRApproverController(
		"OpenShiftAuthenticator",
		operatorCtx.operatorClient,
		operatorCtx.kubeClient.CertificatesV1().CertificateSigningRequests(),
		kubeInformers.Certificates().V1().CertificateSigningRequests(),
		csr.NewLabelFilter(labelSelector),
		csr.NewServiceAccountApprover(
			"openshift-authentication-operator",
			"authentication-operator",
			"CN=system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator",
		),
		eventRecorder,
	)

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc,
		authenticatorCertRequester.Run,
		configObserver.Run,
		webhookAuthController.Run,
		webhookCertsApprover.Run,
		func(ctx context.Context, _ int) { apiServerControllers.Run(ctx) },
	)
	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc,
		apiregistrationInformers.Start,
		kubeInformers.Start,
		migrationInformer.Start,
	)
	return nil
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}

func apiServices() []*apiregistrationv1.APIService {
	var apiServiceGroupVersions = []schema.GroupVersion{
		// these are all the apigroups we manage
		{Group: "oauth.openshift.io", Version: "v1"},
		{Group: "user.openshift.io", Version: "v1"},
	}

	ret := []*apiregistrationv1.APIService{}
	for _, apiServiceGroupVersion := range apiServiceGroupVersions {
		obj := &apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name: apiServiceGroupVersion.Version + "." + apiServiceGroupVersion.Group,
				Annotations: map[string]string{
					"service.alpha.openshift.io/inject-cabundle": "true",
				},
			},
			Spec: apiregistrationv1.APIServiceSpec{
				Group:   apiServiceGroupVersion.Group,
				Version: apiServiceGroupVersion.Version,
				Service: &apiregistrationv1.ServiceReference{
					Namespace: "openshift-oauth-apiserver",
					Name:      "api",
					Port:      utilpointer.Int32Ptr(443),
				},
				GroupPriorityMinimum: 9900,
				VersionPriority:      15,
			},
		}
		ret = append(ret, obj)
	}

	return ret
}

// loadSystemCACertBundle loads the CA bundle from a well-known Red Hat distribution
// location.
// The resulting bundle is either constructed from the contents of the file or
// nil if it fails to load. It is to be used for controllers that generally require a
// cert bundle and not necessary the system trust store contents.
func loadSystemCACertBundle() ([]byte, error) {
	systemCABundle, err := ioutil.ReadFile("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	if err != nil {
		// this may fail route-health checks in proxy environments
		klog.Warningf("unable to read system CA from /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem: %v", err)
		return nil, nil // trust noone
	}

	// test that the cert pool actually contains certs
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(systemCABundle); !ok {
		return nil, fmt.Errorf("no PEM certificates found in the system trust store (/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem)")
	}

	// we can't return the *x509.CertPool object since the controllers are likely
	// to be appending certs to it, but that object offers no way to be deep-copied
	return systemCABundle, nil
}
