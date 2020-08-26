package operator

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	kubemigratorclient "github.com/kubernetes-sigs/kube-storage-version-migrator/pkg/clients/clientset"
	migrationv1alpha1informer "github.com/kubernetes-sigs/kube-storage-version-migrator/pkg/clients/informer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
	utilpointer "k8s.io/utils/pointer"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	authopclient "github.com/openshift/client-go/operator/clientset/versioned"
	authopinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	libgoassets "github.com/openshift/library-go/pkg/operator/apiserver/audit"
	workloadcontroller "github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	apiservercontrollerset "github.com/openshift/library-go/pkg/operator/apiserver/controllerset"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/revisioncontroller"
	"github.com/openshift/library-go/pkg/operator/staleconditions"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/revision"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/configobservercontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/deployment"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/endpointaccessible"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/ingressstate"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/metadata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/payload"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/readiness"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/routercerts"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/serviceca"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/targetversion"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/apiservices"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/assets"
	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/encryptionprovider"
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

	authOperatorClient, err := authopclient.NewForConfig(controllerContext.KubeConfig)
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
	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authOperatorClient, time.Second*30,
		authopinformer.WithTweakListOptions(singleNameListOptions("cluster")),
	)

	operatorClient := &OperatorClient{
		authOperatorConfigInformers,
		authOperatorClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		controllerContext.EventRecorder,
	)

	operatorCtx := &operatorContext{}
	operatorCtx.versionRecorder = status.NewVersionGetter()
	operatorCtx.kubeClient = kubeClient
	operatorCtx.configClient = configClient
	operatorCtx.kubeInformersForNamespaces = kubeInformersForNamespaces
	operatorCtx.resourceSyncController = resourceSyncer
	operatorCtx.operatorClient = operatorClient
	operatorCtx.operatorConfigInformer = configinformer.NewSharedInformerFactoryWithOptions(configClient, resync)

	if err := prepareOauthOperator(controllerContext, operatorCtx); err != nil {
		return err
	}
	if err := prepareOauthAPIServerOperator(ctx, controllerContext, operatorCtx); err != nil {
		return err
	}

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(operatorCtx.operatorClient, controllerContext.EventRecorder)
	logLevelController := loglevel.NewClusterOperatorLoggingController(operatorCtx.operatorClient, controllerContext.EventRecorder)

	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, kubeInformersForNamespaces.Start, authOperatorConfigInformers.Start, operatorCtx.operatorConfigInformer.Start)
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

	// add syncing for the OAuth metadata ConfigMap
	if err := operatorCtx.resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "oauth-openshift"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-metadata"},
	); err != nil {
		return err
	}

	// add syncing for router certs for all cluster ingresses
	if err := operatorCtx.resourceSyncController.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-router-certs"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "router-certs"},
	); err != nil {
		return err
	}

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
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
		operatorCtx.operatorClient,
		operatorCtx.versionRecorder,
		controllerContext.EventRecorder,
	)

	staleConditions := staleconditions.NewRemoveStaleConditionsController(
		[]string{
			// in 4.1.0 this was accidentally in the list.  This can be removed in 4.3.
			"Degraded",

			// As of 4.4, this will appear as a configObserver error
			"FailedRouterSecret",

			// As of 4.6, this will appear as a configObserver error
			"IdentityProviderConfigDegraded",

			"WellKnownEndpointDegraded",
			"WellKnownRouteDegraded",
			"WellKnownAuthConfigDegraded",
			"WellKnownProgressing",
			"OperatorSyncDegraded",
			"RouteHealthDegraded",
			"RouteStatusDegraded",
			"OAuthServerAvailable",
		},
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	staticResourceController := staticresourcecontroller.NewStaticResourceController(
		"OpenshiftAuthenticationStaticResources",
		assets.Asset,
		[]string{
			"oauth-openshift/ns.yaml",
			"oauth-openshift/authentication-clusterrolebinding.yaml",
			"oauth-openshift/cabundle.yaml",
			"oauth-openshift/branding-secret.yaml",
			"oauth-openshift/serviceaccount.yaml",
			"oauth-openshift/oauth-service.yaml",
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
		controllerContext.EventRecorder,
		operatorCtx.operatorConfigInformer.Config().V1().Ingresses(),
		openshiftAuthenticationInformers.Core().V1().Secrets(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
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

	deploymentController := deployment.NewDeploymentController(
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		routeInformersNamespaced,
		operatorCtx.operatorConfigInformer,
		operatorCtx.operatorClient,
		operatorCtx.operatorClient.Client,
		oauthClient.OauthV1().OAuthClients(),
		operatorCtx.kubeClient.AppsV1(),
		bootstrapauthenticator.NewBootstrapUserDataGetter(operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeClient.CoreV1()),
		controllerContext.EventRecorder,
	)

	systemCABundle, err := ioutil.ReadFile("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	if err != nil {
		// this may fail route-health checks in proxy environments
		klog.Warningf("Unable to read system CA from /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem: %v", err)
	}

	targetNsInformers := v1helpers.NewKubeInformersForNamespaces(
		operatorCtx.kubeClient,
		"openshift-authentication",
		"openshift-oauth-apiserver",
	)
	targetVersionController := targetversion.NewTargetVersionController(
		targetNsInformers,
		operatorCtx.operatorConfigInformer,
		routeInformersNamespaced.Route().V1().Routes(),
		oauthClient.OauthV1().OAuthClients(),
		operatorCtx.operatorClient,
		operatorCtx.versionRecorder,
		systemCABundle,
		controllerContext.EventRecorder,
	)

	authRouteCheckController := endpointaccessible.NewOAuthRouteCheckController(
		operatorCtx.operatorClient,
		routeInformersNamespaced.Route().V1().Routes(),
		controllerContext.EventRecorder,
	)

	authServiceCheckController := endpointaccessible.NewOAuthServiceCheckController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication").Core().V1(),
		controllerContext.EventRecorder,
	)

	authServiceEndpointCheckController := endpointaccessible.NewOAuthServiceEndpointsCheckController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-authentication").Core().V1(),
		controllerContext.EventRecorder,
	)

	// TODO remove this controller once we support Removed
	managementStateController := management.NewOperatorManagementStateController("authentication", operatorCtx.operatorClient, controllerContext.EventRecorder)
	management.SetOperatorNotRemovable()

	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc,
		routeInformersNamespaced.Start,
		kubeSystemNamespaceInformers.Start,
		openshiftAuthenticationInformers.Start,
		targetNsInformers.Start,
	)

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc,
		clusterOperatorStatus.Run,
		configObserver.Run,
		deploymentController.Run,
		managementStateController.Run,
		metadataController.Run,
		payloadConfigController.Run,
		routerCertsController.Run,
		serviceCAController.Run,
		staticResourceController.Run,
		targetVersionController.Run,
		wellKnownReadyController.Run,
		authRouteCheckController.Run,
		authServiceCheckController.Run,
		authServiceEndpointCheckController.Run,
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

	nodeProvider := encryptiondeployer.NewDeploymentNodeProvider("openshift-oauth-apiserver", operatorCtx.kubeInformersForNamespaces)
	deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer("revision", "openshift-oauth-apiserver", operatorCtx.kubeInformersForNamespaces, operatorCtx.resourceSyncController, operatorCtx.kubeClient.CoreV1(), operatorCtx.kubeClient.CoreV1(), nodeProvider)
	if err != nil {
		return err
	}
	migrationClient := kubemigratorclient.NewForConfigOrDie(controllerContext.KubeConfig)
	migrationInformer := migrationv1alpha1informer.NewSharedInformerFactory(migrationClient, time.Minute*30)
	migrator := migrators.NewKubeStorageVersionMigrator(migrationClient, migrationInformer.Migration().V1alpha1(), operatorCtx.kubeClient.Discovery())
	encryptionProvider := encryptionprovider.New(
		"openshift-oauth-apiserver",
		"openshift-config-managed",
		"encryption.apiserver.operator.openshift.io/managed-by",
		[]schema.GroupResource{
			{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
			{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
		},
		operatorCtx.kubeInformersForNamespaces,
	)

	authAPIServerWorkload := workload.NewOAuthAPIServerWorkload(
		operatorCtx.operatorClient.Client,
		workloadcontroller.CountNodesFuncWrapper(operatorCtx.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes().Lister()),
		workloadcontroller.EnsureAtMostOnePodPerNode,
		"openshift-oauth-apiserver",
		os.Getenv("IMAGE_OAUTH_APISERVER"),
		os.Getenv("OPERATOR_IMAGE"),
		operatorCtx.kubeClient,
		eventRecorder)

	apiServerControllers, err := apiservercontrollerset.NewAPIServerControllerSet(
		operatorCtx.operatorClient,
		eventRecorder,
	).WithWorkloadController(
		"OAuthAPIServerController",
		"openshift-authentication-operator",
		"openshift-oauth-apiserver",
		os.Getenv("OPERATOR_IMAGE_VERSION"),
		"oauth",
		"APIServer",
		operatorCtx.kubeClient,
		authAPIServerWorkload,
		operatorCtx.configClient.ConfigV1().ClusterOperators(),
		operatorCtx.versionRecorder,
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorClient.Informers.Operator().V1().Authentications().Informer(),
	).WithStaticResourcesController(
		"APIServerStaticResources",
		libgoassets.WithAuditPolicies("audit", "openshift-oauth-apiserver", assets.Asset),
		[]string{
			"oauth-apiserver/ns.yaml",
			"oauth-apiserver/apiserver-clusterrolebinding.yaml",
			"oauth-apiserver/svc.yaml",
			"oauth-apiserver/sa.yaml",
			libgoassets.AuditPoliciesConfigMapFileName,
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
		(&apiservices.WithChangeEvent{
			APIServicesToManage: apiservices.NewAPIServicesToManage(
				operatorCtx.operatorClient.Informers.Operator().V1().Authentications().Lister(),
				func() []*apiregistrationv1.APIService {
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
									"service.alpha.openshift.io/inject-cabundle":   "true",
									"authentication.operator.openshift.io/managed": "true",
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
				}(),
			),
			EventRecorder: eventRecorder,
		}).GetAPIServicesToManage,
		apiregistrationInformers,
		apiregistrationv1Client.ApiregistrationV1(),
		operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		operatorCtx.kubeClient,
	).WithEncryptionControllers(
		"openshift-oauth-apiserver",
		encryptionProvider,
		deployer,
		migrator,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.configClient.ConfigV1().APIServers(),
		operatorCtx.operatorConfigInformer.Config().V1().APIServers(),
		operatorCtx.kubeInformersForNamespaces,
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
	).
		WithoutClusterOperatorStatusController().
		WithoutLogLevelController().
		WithoutConfigUpgradableController().
		PrepareRun()

	if err != nil {
		return err
	}

	manageOAuthAPIController := apiservices.NewManageAPIServicesController(
		"MangeOAuthAPIController",
		deployer,
		operatorCtx.operatorClient.Client,
		operatorCtx.operatorClient.Informers,
		eventRecorder)

	auditPolicyPathGetter, err := libgoassets.NewAuditPolicyPathGetter("/var/run/configmaps/audit")
	if err != nil {
		return err
	}

	configObserver := oauthapiconfigobservercontroller.NewConfigObserverController(
		operatorCtx.operatorClient,
		operatorCtx.kubeInformersForNamespaces,
		operatorCtx.operatorConfigInformer,
		operatorCtx.resourceSyncController,
		auditPolicyPathGetter,
		controllerContext.EventRecorder,
	)

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc,
		configObserver.Run,
		manageOAuthAPIController.Run,
		func(ctx context.Context, _ int) { apiServerControllers.Run(ctx) },
	)
	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, apiregistrationInformers.Start, migrationInformer.Start)
	return nil
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
