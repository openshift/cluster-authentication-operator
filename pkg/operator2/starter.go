package operator2

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/staleconditions"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/configobservercontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/ingressstate"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/routercerts"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/assets"
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

	authOperatorClient, err := authopclient.NewForConfig(controllerContext.KubeConfig)
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

	kubeInformersNamespaced := v1helpers.NewKubeInformersForNamespaces(kubeClient,
		"openshift-authentication",
		"openshift-config",
		"kube-system",
	)

	// short resync period as this drives the check frequency when checking the .well-known endpoint. 20 min is too slow for that.
	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authOperatorClient, time.Second*30,
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
		authOperatorClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		resourceSyncerInformers,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), resourceSyncerInformers),
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
		},
		resourceapply.NewKubeClientHolder(kubeClient),
		operatorClient,
		controllerContext.EventRecorder,
	).AddKubeInformers(kubeInformersNamespaced)

	configObserver := configobservercontroller.NewConfigObserver(
		operatorClient,
		kubeInformersNamespaced,
		configInformers,
		resourceSyncer,
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
		kubeInformersNamespaced.InformersFor("openshift-authentication"),
		kubeInformersNamespaced.InformersFor("kube-system"),
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
			{Group: routev1.GroupName, Resource: "routes", Name: "oauth-openshift", Namespace: "openshift-authentication"},
			{Resource: "services", Name: "oauth-openshift", Namespace: "openshift-authentication"},
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

	staleConditions := staleconditions.NewRemoveStaleConditionsController(
		[]string{
			// in 4.1.0 this was accidentally in the list.  This can be removed in 4.3.
			"Degraded",

			// As of 4.4, this will appear as a configObserver error
			"FailedRouterSecret",

			// As of 4.6, this will appear as a configObserver error
			"IdentityProviderConfigDegraded",
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
		kubeInformersNamespaced.InformersFor("openshift-authentication").Core().V1().Secrets(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"oauth-openshift",
	)

	ingressStateController := ingressstate.NewIngressStateController(
		kubeInformersNamespaced.InformersFor("openshift-authentication"),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		operatorClient,
		"openshift-authentication",
		controllerContext.EventRecorder)

	// TODO remove this controller once we support Removed
	managementStateController := management.NewOperatorManagementStateController("authentication", operatorClient, controllerContext.EventRecorder)
	management.SetOperatorNotRemovable()

	for _, informer := range []interface {
		Start(stopCh <-chan struct{})
	}{
		kubeInformersNamespaced,
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
		configObserver,
		configOverridesController,
		logLevelController,
		managementStateController,
		routerCertsController,
		staleConditions,
		staticResourceController,
	} {
		go controller.Run(ctx, 1)
	}

	go operator.Run(ctx.Done())
	go ingressStateController.Run(1, ctx.Done())

	<-ctx.Done()

	return nil
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
