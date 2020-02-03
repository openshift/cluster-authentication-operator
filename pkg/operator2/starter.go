package operator2

import (
	"context"
	"fmt"
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

func RunOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// protobuf can be used with non custom resources
	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}

	authConfigClient, err := authopclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

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

	configClient, err := configclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}

	kubeInformersNamespaced := informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
		informers.WithNamespace("openshift-authentication"),
	)

	kubeSystemNamespaceInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
		informers.WithNamespace("kube-system"),
	)

	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authConfigClient, resync,
		authopinformer.WithTweakListOptions(singleNameListOptions("cluster")),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace("openshift-authentication"),
		routeinformer.WithTweakListOptions(singleNameListOptions("oauth-openshift")),
	)

	// do not use WithTweakListOptions here as top level configs are all called "cluster"
	// whereas our cluster operator instance is called "authentication" (there is no OR support)
	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, resync)

	resourceSyncerInformers := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
	)

	operatorClient := &OperatorClient{
		authOperatorConfigInformers,
		authConfigClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		resourceSyncerInformers,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		controllerContext.EventRecorder,
	)

	// add syncing for the OAuth metadata ConfigMap
	if err := resourceSyncer.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "oauth-openshift"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-metadata"},
	); err != nil {
		return err
	}

	// add syncing for router certs for all cluster ingresses
	if err := resourceSyncer.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-router-certs"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "router-certs"},
	); err != nil {
		return err
	}

	// add syncing for the console-config ConfigMap (indirect watch for changes)
	if err := resourceSyncer.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-system-console-config"},
		resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: "console-config"},
	); err != nil {
		return err
	}

	versionGetter := status.NewVersionGetter()

	operator := NewAuthenticationOperator(
		*operatorClient,
		oauthClient.OauthV1(),
		kubeInformersNamespaced,
		kubeSystemNamespaceInformers,
		kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		configClient,
		versionGetter,
		controllerContext.EventRecorder,
		resourceSyncer,
	)

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		"authentication",
		[]configv1.ObjectReference{
			{Group: operatorv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "infrastructures", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "oauths", Name: "cluster"},
			{Group: routev1.GroupName, Resource: "routes", Name: "oauth-openshift"},
			{Resource: "services", Name: "oauth-openshift"},
			{Resource: "namespaces", Name: "openshift-config"},
			{Resource: "namespaces", Name: "openshift-config-managed"},
			{Resource: "namespaces", Name: "openshift-authentication"},
			{Resource: "namespaces", Name: "openshift-authentication-operator"},
			{Resource: "namespaces", Name: "openshift-ingress"},
		},
		configClient.ConfigV1(),
		configInformers.Config().V1().ClusterOperators(),
		operatorClient,
		versionGetter,
		controllerContext.EventRecorder,
	)

	staleConditions := staleconditions.NewRemoveStaleConditions(
		[]string{
			// in 4.1.0 this was accidentally in the list.  This can be removed in 4.3.
			"Degraded",
		},
		operatorClient,
		controllerContext.EventRecorder,
	)

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(operatorClient, controllerContext.EventRecorder)
	logLevelController := loglevel.NewClusterOperatorLoggingController(operatorClient, controllerContext.EventRecorder)

	routerCertsController := routercerts.NewRouterCertsDomainValidationController(
		operatorClient,
		controllerContext.EventRecorder,
		configInformers.Config().V1().Ingresses(),
		kubeInformersNamespaced.Core().V1().Secrets(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"oauth-openshift",
	)

	ingressStateController := ingressstate.NewIngressStateController(
		kubeInformersNamespaced,
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		operatorClient,
		"openshift-authentication",
		controllerContext.EventRecorder)

	// TODO remove this controller once we support Removed
	managementStateController := management.NewOperatorManagementStateController("authentication", operatorClient, controllerContext.EventRecorder)
	management.SetOperatorNotRemovable()
	// TODO move to config observers
	// configobserver.NewConfigObserver(...)

	for _, informer := range []interface {
		Start(stopCh <-chan struct{})
	}{
		kubeInformersNamespaced,
		kubeSystemNamespaceInformers,
		authOperatorConfigInformers,
		routeInformersNamespaced,
		configInformers,
		resourceSyncerInformers,
	} {
		informer.Start(ctx.Done())
	}

	for _, controller := range []interface {
		Run(ctx context.Context, workers int)
	}{
		resourceSyncer,
		clusterOperatorStatus,
		configOverridesController,
		logLevelController,
		routerCertsController,
		managementStateController,
	} {
		go controller.Run(ctx, 1)
	}

	go operator.Run(ctx.Done())
	go staleConditions.Run(ctx, 1)
	go ingressStateController.Run(1, ctx.Done())

	<-ctx.Done()

	return fmt.Errorf("stopped")
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
