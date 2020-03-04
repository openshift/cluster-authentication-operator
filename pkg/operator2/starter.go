package operator2

import (
	"context"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/workload"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/klog"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

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
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/staleconditions"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controller/ingressstate"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/routercerts"
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

	resourceSyncController *resourcesynccontroller.ResourceSyncController

	informersToRunFunc   []func(stopCh <-chan struct{})
	controllersToRunFunc []func(ctx context.Context, workers int)
}

// RunOperator prepares and runs both operators OAuth and OAuthAPIServer
// TODO: in the future we might move each operator to its onw pkg
// TODO: consider using the new operator framework
func RunOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	opCtx := &operatorContext{}

	// protobuf can be used with non custom resources
	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	configClient, err := configclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

	authConfigClient, err := authopclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
		"openshift-oauth-apiserver",
		"openshift-authentication-operator",
	)

	// short resync period as this drives the check frequency when checking the .well-known endpoint. 20 min is too slow for that.
	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authConfigClient, time.Second*30,
		authopinformer.WithTweakListOptions(singleNameListOptions("cluster")),
	)

	operatorClient := &OperatorClient{
		authOperatorConfigInformers,
		authConfigClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		controllerContext.EventRecorder,
	)

	opCtx.versionRecorder = status.NewVersionGetter()
	opCtx.kubeClient = kubeClient
	opCtx.configClient = configClient
	opCtx.kubeInformersForNamespaces = kubeInformersForNamespaces
	opCtx.resourceSyncController = resourceSyncer
	opCtx.operatorClient = operatorClient

	if err := prepareOauthOperator(ctx, controllerContext, opCtx); err != nil {
		return err
	}
	if err := prepareOauthAPIServerOperator(opCtx); err != nil {
		return err
	}

	opCtx.informersToRunFunc = append(opCtx.informersToRunFunc, kubeInformersForNamespaces.Start)
	opCtx.informersToRunFunc = append(opCtx.informersToRunFunc, authOperatorConfigInformers.Start)

	opCtx.controllersToRunFunc = append(opCtx.controllersToRunFunc, resourceSyncer.Run)

	for _, informerToRunFn := range opCtx.informersToRunFunc {
		informerToRunFn(ctx.Done())
	}

	for _, controllerRunFn := range opCtx.controllersToRunFunc {
		go controllerRunFn(ctx, 1)
	}

	<-ctx.Done()
	return nil
}


func prepareOauthOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext, operatorCtx *operatorContext) error {
	// protobuf can be used with non custom resources
	// protobuf can be used with non custom resources
	routeClient, err := routeclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	// protobuf can be used with non custom resources
	oauthClient, err := oauthclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	kubeInformersNamespaced := informers.NewSharedInformerFactoryWithOptions(operatorCtx.kubeClient, resync,
		informers.WithNamespace("openshift-authentication"),
	)

	kubeSystemNamespaceInformers := informers.NewSharedInformerFactoryWithOptions(operatorCtx.kubeClient, resync,
		informers.WithNamespace("kube-system"),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace("openshift-authentication"),
		routeinformer.WithTweakListOptions(singleNameListOptions("oauth-openshift")),
	)

	// do not use WithTweakListOptions here as top level configs are all called "cluster"
	// whereas our cluster operator instance is called "authentication" (there is no OR support)
	configInformers := configinformer.NewSharedInformerFactoryWithOptions(operatorCtx.configClient, resync)

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

	// add syncing for the console-config ConfigMap (indirect watch for changes)
	if err := operatorCtx.resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-console-config"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "console-config"},
	); err != nil {
		return err
	}

	operator := NewAuthenticationOperator(
		*operatorCtx.operatorClient,
		oauthClient.OauthV1(),
		kubeInformersNamespaced,
		kubeSystemNamespaceInformers,
		operatorCtx.kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		operatorCtx.configClient,
		operatorCtx.versionRecorder,
		controllerContext.EventRecorder,
		operatorCtx.resourceSyncController,
	)

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		"authentication",
		[]configv1.ObjectReference{
			{Group: operatorv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "infrastructures", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "oauths", Name: "cluster"},
			{Group: routev1.GroupName, Resource: "routes", Name: "oauth-openshift", Namespace: "openshift-authentication"},
			{Resource: "services", Name: "oauth-openshift"},
			{Resource: "namespaces", Name: "openshift-config"},
			{Resource: "namespaces", Name: "openshift-config-managed"},
			{Resource: "namespaces", Name: "openshift-authentication"},
			{Resource: "namespaces", Name: "openshift-authentication-operator"},
			{Resource: "namespaces", Name: "openshift-ingress"},
			{Resource: "namespaces", Name: "openshift-oauth-apiserver"},
		},
		operatorCtx.configClient.ConfigV1(),
		configInformers.Config().V1().ClusterOperators(),
		operatorCtx.operatorClient,
		operatorCtx.versionRecorder,
		controllerContext.EventRecorder,
	)

	staleConditions := staleconditions.NewRemoveStaleConditionsController(
		[]string{
			// in 4.1.0 this was accidentally in the list.  This can be removed in 4.3.
			"Degraded",
		},
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
	)

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(operatorCtx.operatorClient, controllerContext.EventRecorder)
	logLevelController := loglevel.NewClusterOperatorLoggingController(operatorCtx.operatorClient, controllerContext.EventRecorder)

	routerCertsController := routercerts.NewRouterCertsDomainValidationController(
		operatorCtx.operatorClient,
		controllerContext.EventRecorder,
		configInformers.Config().V1().Ingresses(),
		kubeInformersNamespaced.Core().V1().Secrets(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"oauth-openshift",
	)

	ingressStateController := ingressstate.NewIngressStateController(
		kubeInformersNamespaced,
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.kubeClient.CoreV1(),
		operatorCtx.operatorClient,
		"openshift-authentication",
		controllerContext.EventRecorder)

	// TODO remove this controller once we support Removed
	managementStateController := management.NewOperatorManagementStateController("authentication", operatorCtx.operatorClient, controllerContext.EventRecorder)
	management.SetOperatorNotRemovable()
	// TODO move to config observers
	// configobserver.NewConfigObserver(...)

	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, kubeInformersNamespaced.Start)
	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, routeInformersNamespaced.Start)
	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, configInformers.Start)
	operatorCtx.informersToRunFunc = append(operatorCtx.informersToRunFunc, kubeSystemNamespaceInformers.Start)

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, clusterOperatorStatus.Run)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, configOverridesController.Run)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, logLevelController.Run)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, routerCertsController.Run)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, managementStateController.Run)
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, func(ctx context.Context, workers int) { staleConditions.Run(workers, ctx.Done()) })
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, func(ctx context.Context, workers int) { ingressStateController.Run(workers, ctx.Done()) })
	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, func(ctx context.Context, _ int) { operator.Run(ctx.Done()) })

	return nil
}

func prepareOauthAPIServerOperator(operatorCtx *operatorContext) error {

	controllerRef, err := events.GetControllerReferenceForCurrentPod(operatorCtx.kubeClient, "openshift-authentication-operator", nil)
	if err != nil {
		klog.Warningf("unable to get owner reference (falling back to namespace): %v", err)
	}
	eventRecorder := events.NewKubeRecorder(operatorCtx.kubeClient.CoreV1().Events("openshift-authentication-operator"), "authentication", controllerRef)

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

	workloadController := workload.NewController(
		"OAuthAPIServerController",
		"openshift-authentication-operator",
		"openshift-oauth-apiserver",
		operatorCtx.operatorClient,
		operatorCtx.kubeClient,
		workload.NewOAuthAPIServerWorkload(operatorCtx.operatorClient.Client, "openshift-oauth-apiserver", os.Getenv("IMAGE_OAUTH_APISERVER"), os.Getenv("OPERATOR_IMAGE"), operatorCtx.kubeClient, eventRecorder, operatorCtx.versionRecorder).Sync,
		operatorCtx.configClient.ConfigV1().ClusterOperators(),
		eventRecorder, operatorCtx.versionRecorder).
		AddInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().ConfigMaps().Informer()). // reactor for etcd-serving-ca
		AddInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Secrets().Informer()).    // reactor for etcd-client
		AddInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().ServiceAccounts().Informer()).
		AddInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Services().Informer()).
		AddInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Apps().V1().DaemonSets().Informer()).
		AddInformer(operatorCtx.operatorClient.Informers.Operator().V1().Authentications().Informer()).
		AddNamespaceInformer(operatorCtx.kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Namespaces().Informer())

	operatorCtx.controllersToRunFunc = append(operatorCtx.controllersToRunFunc, workloadController.Run)

	return nil
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
