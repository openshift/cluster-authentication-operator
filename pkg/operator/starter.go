package operator

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/openshift/multi-operator-manager/pkg/library/libraryapplyconfiguration"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/cluster-authentication-operator/bindata"
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
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/termination"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/trustdistribution"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/webhookauthenticator"
	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/configobservercontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/workload"
	"github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	workloadcontroller "github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	apiservercontrollerset "github.com/openshift/library-go/pkg/operator/apiserver/controllerset"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/csr"
	"github.com/openshift/library-go/pkg/operator/encryption"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/managementstatecontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/revisioncontroller"
	"github.com/openshift/library-go/pkg/operator/staleconditions"
	staticpodcommon "github.com/openshift/library-go/pkg/operator/staticpod/controller/common"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/revision"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	certapiv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	utilpointer "k8s.io/utils/pointer"
)

const (
	resync = 20 * time.Minute
)

// RunOperator prepares and runs both operators OAuth and OAuthAPIServer
// TODO: in the future we might move each operator to its own pkg
// TODO: consider using the new operator framework
func RunOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	operatorInput, err := CreateControllerInputFromControllerContext(ctx, controllerContext)
	if err != nil {
		return err
	}
	operatorStarter, err := CreateOperatorStarter(ctx, operatorInput)
	if err != nil {
		return err
	}
	if err := operatorStarter.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}

func prepareOauthOperator(
	ctx context.Context,
	authOperatorInput *authenticationOperatorInput,
	informerFactories authenticationOperatorInformerFactories,
	resourceSyncController *resourcesynccontroller.ResourceSyncController,
	versionRecorder status.VersionGetter,
) ([]libraryapplyconfiguration.NamedRunOnce, []libraryapplyconfiguration.RunFunc, error) {

	clusterVersion, err := authOperatorInput.configClient.ConfigV1().ClusterVersions().Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	enabledClusterCapabilities := sets.NewString()
	for _, v := range clusterVersion.Status.Capabilities.EnabledCapabilities {
		enabledClusterCapabilities.Insert(string(v))
	}

	// add syncing for the OAuth metadata ConfigMap
	if err := resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "oauth-openshift"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-metadata"},
	); err != nil {
		return nil, nil, err
	}

	staleConditions := staleconditions.NewRemoveStaleConditionsController(
		"openshift-authentication",
		[]string{
			// condition type removed in 4.17.z
			"",
		},
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
	)

	staticResourceController := staticresourcecontroller.NewStaticResourceController(
		"OpenshiftAuthenticationStaticResources",
		bindata.Asset,
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
		resourceapply.NewKubeClientHolder(authOperatorInput.kubeClient),
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
	).AddKubeInformers(informerFactories.kubeInformersForNamespaces)

	configObserver := configobservercontroller.NewConfigObserver(
		authOperatorInput.authenticationOperatorClient,
		informerFactories.kubeInformersForNamespaces,
		informerFactories.operatorConfigInformer,
		resourceSyncController,
		enabledClusterCapabilities,
		authOperatorInput.eventRecorder,
	)

	routerCertsController := routercerts.NewRouterCertsDomainValidationController(
		"openshift-authentication",
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.eventRecorder,
		informerFactories.operatorConfigInformer.Config().V1().Ingresses(),
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication").Core().V1().Secrets(),
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets(),
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().ConfigMaps(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"v4-0-config-system-custom-router-certs",
		"oauth-openshift",
	)

	ingressStateController := ingressstate.NewIngressStateController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.authenticationOperatorClient,
		"openshift-authentication",
		authOperatorInput.eventRecorder)

	wellKnownReadyController := readiness.NewWellKnownReadyController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces,
		informerFactories.operatorConfigInformer,
		informerFactories.namespacedOpenshiftAuthenticationRoutes.Route().V1().Routes(),
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
	)

	metadataController := metadata.NewMetadataController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		informerFactories.operatorConfigInformer,
		informerFactories.namespacedOpenshiftAuthenticationRoutes,
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.routeClient.RouteV1().Routes("openshift-authentication"),
		authOperatorInput.configClient.ConfigV1().Authentications(),
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
	)

	serviceCAController := serviceca.NewServiceCAController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		informerFactories.operatorConfigInformer,
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
	)

	payloadConfigController := payload.NewPayloadConfigController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.authenticationOperatorClient,
		informerFactories.namespacedOpenshiftAuthenticationRoutes.Route().V1().Routes(),
		authOperatorInput.eventRecorder,
	)

	oauthClientsController := oauthclientscontroller.NewOAuthClientsController(
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.oauthClient.OauthV1().OAuthClients(),
		informerFactories.oauthInformers,
		informerFactories.namespacedOpenshiftAuthenticationRoutes,
		informerFactories.operatorConfigInformer,
		authOperatorInput.eventRecorder,
	)

	deploymentController := deployment.NewOAuthServerWorkloadController(
		authOperatorInput.authenticationOperatorClient,
		workloadcontroller.CountNodesFuncWrapper(informerFactories.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes().Lister()),
		workloadcontroller.EnsureAtMostOnePodPerNode,
		authOperatorInput.kubeClient,
		informerFactories.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes(),
		authOperatorInput.configClient.ConfigV1().ClusterOperators(),
		informerFactories.operatorConfigInformer,
		informerFactories.namespacedOpenshiftAuthenticationRoutes,
		bootstrapauthenticator.NewBootstrapUserDataGetter(authOperatorInput.kubeClient.CoreV1(), authOperatorInput.kubeClient.CoreV1()),
		authOperatorInput.eventRecorder,
		versionRecorder,
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
	)

	workersAvailableController := ingressnodesavailable.NewIngressNodesAvailableController(
		"openshift-authentication",
		authOperatorInput.authenticationOperatorClient,
		informerFactories.operatorInformer.Operator().V1().IngressControllers(),
		authOperatorInput.eventRecorder,
		informerFactories.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes(),
	)

	systemCABundle, err := loadSystemCACertBundle()
	if err != nil {
		return nil, nil, err
	}

	authRouteCheckController := oauthendpoints.NewOAuthRouteCheckController(
		authOperatorInput.authenticationOperatorClient,
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-config-managed"),
		informerFactories.namespacedOpenshiftAuthenticationRoutes.Route().V1().Routes(),
		informerFactories.operatorConfigInformer.Config().V1().Ingresses(),
		systemCABundle,
		authOperatorInput.eventRecorder,
	)

	authServiceCheckController := oauthendpoints.NewOAuthServiceCheckController(
		authOperatorInput.authenticationOperatorClient,
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		authOperatorInput.eventRecorder,
	)

	authServiceEndpointCheckController := oauthendpoints.NewOAuthServiceEndpointsCheckController(
		authOperatorInput.authenticationOperatorClient,
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-authentication"),
		authOperatorInput.eventRecorder,
	)

	proxyConfigController := proxyconfig.NewProxyConfigChecker(
		informerFactories.namespacedOpenshiftAuthenticationRoutes.Route().V1().Routes(),
		informerFactories.kubeInformersForNamespaces,
		"openshift-authentication",
		"oauth-openshift",
		map[string][]string{
			"openshift-authentication-operator": {"trusted-ca-bundle"},
			"openshift-config-managed":          {"default-ingress-cert"},
		},
		authOperatorInput.eventRecorder,
		authOperatorInput.authenticationOperatorClient,
	)

	customRouteController := componentroutesecretsync.NewCustomRouteController(
		componentroutesecretsync.OAuthComponentRouteNamespace,
		componentroutesecretsync.OAuthComponentRouteName,
		"openshift-authentication",
		"v4-0-config-system-custom-router-certs",
		informerFactories.operatorConfigInformer.Config().V1().Ingresses(),
		authOperatorInput.configClient.ConfigV1().Ingresses(),
		informerFactories.namespacedOpenshiftAuthenticationRoutes.Route().V1().Routes(),
		authOperatorInput.routeClient.RouteV1().Routes("openshift-authentication"),
		informerFactories.kubeInformersForNamespaces,
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.eventRecorder,
		resourceSyncController,
	)

	// TODO remove this controller once we support Removed
	managementStateController := managementstatecontroller.NewOperatorManagementStateController("authentication", authOperatorInput.authenticationOperatorClient, authOperatorInput.eventRecorder)
	management.SetOperatorNotRemovable()

	trustDistributionController := trustdistribution.NewTrustDistributionController(
		authOperatorInput.kubeClient.CoreV1(),
		informerFactories.kubeInformersForNamespaces,
		informerFactories.operatorConfigInformer.Config().V1().Ingresses(),
		authOperatorInput.eventRecorder,
	)

	runOnceFns := []libraryapplyconfiguration.NamedRunOnce{
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-configObserver", configObserver.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-deploymentController", deploymentController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-managementStateController", managementStateController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-metadataController", metadataController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-oauthClientsController", oauthClientsController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-payloadConfigController", payloadConfigController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-routerCertsController", routerCertsController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-serviceCAController", serviceCAController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-staticResourceController", staticResourceController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-wellKnownReadyController", wellKnownReadyController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-authRouteCheckController", authRouteCheckController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-authServiceCheckController", authServiceCheckController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-authServiceEndpointCheckController", authServiceEndpointCheckController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-workersAvailableController", workersAvailableController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-proxyConfigController", proxyConfigController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-customRouteController", customRouteController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-trustDistributionController", trustDistributionController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-staleConditions", staleConditions.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-ingressStateController", ingressStateController.Sync),
	}

	runFns := []libraryapplyconfiguration.RunFunc{
		libraryapplyconfiguration.AdaptRunFn(configObserver.Run),
		libraryapplyconfiguration.AdaptRunFn(deploymentController.Run),
		libraryapplyconfiguration.AdaptRunFn(managementStateController.Run),
		libraryapplyconfiguration.AdaptRunFn(metadataController.Run),
		libraryapplyconfiguration.AdaptRunFn(oauthClientsController.Run),
		libraryapplyconfiguration.AdaptRunFn(payloadConfigController.Run),
		libraryapplyconfiguration.AdaptRunFn(routerCertsController.Run),
		libraryapplyconfiguration.AdaptRunFn(serviceCAController.Run),
		libraryapplyconfiguration.AdaptRunFn(staticResourceController.Run),
		libraryapplyconfiguration.AdaptRunFn(wellKnownReadyController.Run),
		libraryapplyconfiguration.AdaptRunFn(authRouteCheckController.Run),
		libraryapplyconfiguration.AdaptRunFn(authServiceCheckController.Run),
		libraryapplyconfiguration.AdaptRunFn(authServiceEndpointCheckController.Run),
		libraryapplyconfiguration.AdaptRunFn(workersAvailableController.Run),
		libraryapplyconfiguration.AdaptRunFn(proxyConfigController.Run),
		libraryapplyconfiguration.AdaptRunFn(customRouteController.Run),
		libraryapplyconfiguration.AdaptRunFn(trustDistributionController.Run),
		libraryapplyconfiguration.AdaptRunFn(staleConditions.Run),
		libraryapplyconfiguration.AdaptRunFn(ingressStateController.Run),
	}

	if !enabledClusterCapabilities.Has("Console") {
		// This controller is only necessary if the console capability is not yet enabled in the cluster.
		// Once the console capability is enabled, this controller will restart the auth operator and next
		// time it comes up, the console cap will already be enabled and this controller won't be added.
		terminationController := termination.NewTerminationController(
			informerFactories.operatorConfigInformer,
			authOperatorInput.eventRecorder,
		)
		runOnceFns = append(runOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-terminationController", terminationController.Sync))
		runFns = append(runFns, libraryapplyconfiguration.AdaptRunFn(terminationController.Run))
	}

	return runOnceFns, runFns, nil
}

func prepareOauthAPIServerOperator(
	ctx context.Context,
	authOperatorInput *authenticationOperatorInput,
	informerFactories authenticationOperatorInformerFactories,
	resourceSyncController *resourcesynccontroller.ResourceSyncController,
	versionRecorder status.VersionGetter,
) ([]libraryapplyconfiguration.NamedRunOnce, []libraryapplyconfiguration.RunFunc, error) {
	eventRecorder := authOperatorInput.eventRecorder.ForComponent("oauth-apiserver")

	// add syncing for etcd certs for oauthapi-server
	if err := resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-oauth-apiserver", Name: "etcd-serving-ca"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "etcd-serving-ca"},
	); err != nil {
		return nil, nil, err
	}
	if err := resourceSyncController.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-oauth-apiserver", Name: "etcd-client"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "etcd-client"},
	); err != nil {
		return nil, nil, err
	}

	nodeProvider := encryptiondeployer.NewDeploymentNodeProvider("openshift-oauth-apiserver", informerFactories.kubeInformersForNamespaces)
	deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer("revision", "openshift-oauth-apiserver", informerFactories.kubeInformersForNamespaces, authOperatorInput.kubeClient.CoreV1(), authOperatorInput.kubeClient.CoreV1(), nodeProvider)
	if err != nil {
		return nil, nil, err
	}
	migrator := migrators.NewKubeStorageVersionMigrator(authOperatorInput.migrationClient, informerFactories.migrationInformer.Migration().V1alpha1(), authOperatorInput.kubeClient.Discovery())

	authAPIServerWorkload := workload.NewOAuthAPIServerWorkload(
		authOperatorInput.authenticationOperatorClient,
		workloadcontroller.CountNodesFuncWrapper(informerFactories.kubeInformersForNamespaces.InformersFor("").Core().V1().Nodes().Lister()),
		workloadcontroller.EnsureAtMostOnePodPerNode,
		"openshift-oauth-apiserver",
		os.Getenv("IMAGE_OAUTH_APISERVER"),
		os.Getenv("OPERATOR_IMAGE"),
		authOperatorInput.kubeClient,
		versionRecorder)

	infra, err := authOperatorInput.configClient.ConfigV1().Infrastructures().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		klog.Warningf("unexpectedly no infrastructure resource found, assuming non SingleReplicaTopologyMode controlPlaneTopology: %v", err)
	} else if err != nil {
		return nil, nil, err
	}
	var statusControllerOptions []func(*status.StatusSyncer) *status.StatusSyncer
	if infra == nil || infra.Status.ControlPlaneTopology != configv1.SingleReplicaTopologyMode {
		statusControllerOptions = append(statusControllerOptions, apiservercontrollerset.WithStatusControllerPdbCompatibleHighInertia("(APIServer|OAuthServer)"))
	}

	const apiServerConditionsPrefix = "APIServer"

	apiServerControllers, err := apiservercontrollerset.NewAPIServerControllerSet(
		"oauth-apiserver",
		authOperatorInput.authenticationOperatorClient,
		eventRecorder,
	).WithWorkloadController(
		"OAuthAPIServerController",
		"openshift-authentication-operator",
		"openshift-oauth-apiserver",
		os.Getenv("OPERATOR_IMAGE_VERSION"),
		"oauth",
		apiServerConditionsPrefix,
		authOperatorInput.kubeClient,
		authAPIServerWorkload,
		authOperatorInput.configClient.ConfigV1().ClusterOperators(),
		versionRecorder,
		informerFactories.kubeInformersForNamespaces,
		authOperatorInput.authenticationOperatorClient.Informer(), // TODO update the library so that the operator client informer is automatically added.
	).WithStaticResourcesController(
		"APIServerStaticResources",
		bindata.Asset,
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
					isSNO, precheckSucceeded, err := staticpodcommon.NewIsSingleNodePlatformFn(
						informerFactories.operatorConfigInformer.Config().V1().Infrastructures(),
					)()
					if err != nil {
						klog.Errorf("NewIsSingleNodePlatformFn failed: %v", err)
						return false
					}
					if !precheckSucceeded {
						klog.V(4).Infof("NewIsSingleNodePlatformFn precheck did not succeed, skipping")
						return false
					}
					return !isSNO
				},
				ShouldDeleteFn: func() bool {
					isSNO, precheckSucceeded, err := staticpodcommon.NewIsSingleNodePlatformFn(
						informerFactories.operatorConfigInformer.Config().V1().Infrastructures(),
					)()
					if err != nil {
						klog.Errorf("NewIsSingleNodePlatformFn failed: %v", err)
						return false
					}
					if !precheckSucceeded {
						klog.V(4).Infof("NewIsSingleNodePlatformFn precheck did not succeed, skipping")
						return false
					}
					return isSNO
				},
			},
		},

		informerFactories.kubeInformersForNamespaces,
		authOperatorInput.kubeClient,
	).WithRevisionController(
		"openshift-oauth-apiserver",
		[]revisioncontroller.RevisionResource{{
			Name: "audit", // defined in library-go
		}},
		[]revision.RevisionResource{{
			Name:     "encryption-config",
			Optional: true,
		}},
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		// TODO looks like the concept of revisions has leaked into at least one non-static pod operator.  Probably end up making this a flavor of regular OperatorStatus?
		authOperatorInput.authenticationOperatorClient,
		v1helpers.CachedConfigMapGetter(authOperatorInput.kubeClient.CoreV1(), informerFactories.kubeInformersForNamespaces),
		v1helpers.CachedSecretGetter(authOperatorInput.kubeClient.CoreV1(), informerFactories.kubeInformersForNamespaces),
	).WithAPIServiceController(
		"openshift-apiserver",
		"openshift-oauth-apiserver",
		func() ([]*apiregistrationv1.APIService, []*apiregistrationv1.APIService, error) {
			return apiServices(), nil, nil
		},
		informerFactories.apiregistrationInformers,
		authOperatorInput.apiregistrationv1Client.ApiregistrationV1(),
		informerFactories.kubeInformersForNamespaces,
		authOperatorInput.kubeClient,
	).WithEncryptionControllers(
		"openshift-oauth-apiserver",
		encryption.StaticEncryptionProvider{
			schema.GroupResource{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
			schema.GroupResource{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
		},
		deployer,
		migrator,
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.configClient.ConfigV1().APIServers(),
		informerFactories.operatorConfigInformer.Config().V1().APIServers(),
		informerFactories.kubeInformersForNamespaces,
		resourceSyncController,
	).WithUnsupportedConfigPrefixForEncryptionControllers(
		oauthapiconfigobservercontroller.OAuthAPIServerConfigPrefix,
	).WithFinalizerController(
		"openshift-oauth-apiserver",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		authOperatorInput.kubeClient.CoreV1(),
	).WithSecretRevisionPruneController(
		"openshift-oauth-apiserver",
		[]string{"encryption-config-"},
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.kubeClient.CoreV1(),
		informerFactories.kubeInformersForNamespaces,
	).WithAuditPolicyController(
		"openshift-oauth-apiserver",
		"audit",
		informerFactories.operatorConfigInformer.Config().V1().APIServers().Lister(),
		informerFactories.operatorConfigInformer,
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		authOperatorInput.kubeClient,
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
			authOperatorInput.configClient.ConfigV1(),
			informerFactories.operatorConfigInformer.Config().V1().ClusterOperators(),
			versionRecorder,
			statusControllerOptions...,
		).
		WithoutLogLevelController().
		WithoutConfigUpgradableController().
		PrepareRun()

	if err != nil {
		return nil, nil, err
	}

	configObserver := oauthapiconfigobservercontroller.NewConfigObserverController(
		authOperatorInput.authenticationOperatorClient,
		informerFactories.kubeInformersForNamespaces,
		informerFactories.operatorConfigInformer,
		resourceSyncController,
		authOperatorInput.eventRecorder,
	)

	webhookAuthController := webhookauthenticator.NewWebhookAuthenticatorController(
		"openshift-authentication",
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver"),
		informerFactories.operatorConfigInformer,
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.kubeClient.CoreV1(),
		authOperatorInput.configClient.ConfigV1().Authentications(),
		authOperatorInput.authenticationOperatorClient,
		versionRecorder,
		eventRecorder,
	)

	csrDuration := time.Hour * 24 * 30
	authenticatorCertRequester, err := csr.NewClientCertificateController(
		csr.ClientCertOption{
			SecretNamespace: "openshift-oauth-apiserver",
			SecretName:      "openshift-authenticator-certs",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "apiserver-auth",
			},
		},
		csr.CSROption{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "system:openshift:openshift-authenticator-",
				Labels:       map[string]string{"authentication.openshift.io/csr": "openshift-authenticator"},
			},
			Subject:             &pkix.Name{CommonName: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
			SignerName:          certapiv1.KubeAPIServerClientSignerName,
			CertificateDuration: &csrDuration,
		},
		informerFactories.kubeInformers.Certificates().V1().CertificateSigningRequests(),
		authOperatorInput.kubeClient.CertificatesV1().CertificateSigningRequests(),
		informerFactories.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Secrets(),
		authOperatorInput.kubeClient.CoreV1(),
		eventRecorder,
		"OpenShiftAuthenticatorCertRequester",
	)
	if err != nil {
		return nil, nil, err
	}

	labelsReq, err := labels.NewRequirement("authentication.openshift.io/csr", selection.Equals, []string{"openshift-authenticator"})
	if err != nil {
		return nil, nil, err
	}
	labelSelector := labels.NewSelector().Add(*labelsReq)

	webhookCertsApprover := csr.NewCSRApproverController(
		"OpenShiftAuthenticator",
		authOperatorInput.authenticationOperatorClient,
		authOperatorInput.kubeClient.CertificatesV1().CertificateSigningRequests(),
		informerFactories.kubeInformers.Certificates().V1().CertificateSigningRequests(),
		csr.NewLabelFilter(labelSelector),
		csr.NewServiceAccountApprover(
			"openshift-authentication-operator",
			"authentication-operator",
			"CN=system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator",
		),
		eventRecorder,
	)

	runOnceFns := []libraryapplyconfiguration.NamedRunOnce{
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-other-configObserver", configObserver.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-authenticatorCertRequester", authenticatorCertRequester.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-webhookAuthController", webhookAuthController.Sync),
		libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-webhookCertsApprover", webhookCertsApprover.Sync),
	}
	for _, apiServerController := range apiServerControllers.Controllers() {
		runOnceFns = append(runOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, apiServerController.Name(), apiServerController.Sync))
	}

	runFns := []libraryapplyconfiguration.RunFunc{
		libraryapplyconfiguration.AdaptRunFn(configObserver.Run),
		libraryapplyconfiguration.AdaptRunFn(authenticatorCertRequester.Run),
		libraryapplyconfiguration.AdaptRunFn(webhookAuthController.Run),
		libraryapplyconfiguration.AdaptRunFn(webhookCertsApprover.Run),
		libraryapplyconfiguration.AdaptRunFn(func(ctx context.Context, _ int) { apiServerControllers.Run(ctx) }),
	}

	return runOnceFns, runFns, nil
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

func extractOperatorSpec(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	castObj := &operatorv1.Authentication{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to Authentication: %w", err)
	}
	ret, err := applyoperatorv1.ExtractAuthentication(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}
	if ret.Spec == nil {
		return nil, nil
	}
	return &ret.Spec.OperatorSpecApplyConfiguration, nil
}

func extractOperatorStatus(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	castObj := &operatorv1.Authentication{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to Authentication: %w", err)
	}
	ret, err := applyoperatorv1.ExtractAuthenticationStatus(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}

	if ret.Status == nil {
		return nil, nil
	}
	return &ret.Status.OperatorStatusApplyConfiguration, nil
}
