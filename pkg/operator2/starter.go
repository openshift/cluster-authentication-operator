package operator2

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
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

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/routecontroller"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/routercerts"
	authopclient "github.com/openshift/cluster-authentication-operator/pkg/operatorclient"
)

const (
	resync = 20 * time.Minute
)

func RunOperator(ctx *controllercmd.ControllerContext) error {
	// protobuf can be used with non custom resources
	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}

	authConfigClient, err := operatorclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	// protobuf can be used with non custom resources
	routeClient, err := routeclient.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}

	// protobuf can be used with non custom resources
	oauthClient, err := oauthclient.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}

	configClient, err := configclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	kubeInformersNamespaced := informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
		informers.WithNamespace("openshift-authentication"),
	)

	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authConfigClient, resync,
		authopinformer.WithTweakListOptions(singleNameListOptions("cluster")),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace("openshift-authentication"),
		routeinformer.WithTweakListOptions(singleNameListOptions("oauth-openshift")),
	)

	oauthClientInformers := oauthinformer.NewSharedInformerFactoryWithOptions(oauthClient, resync)

	// do not use WithTweakListOptions here as top level configs are all called "cluster"
	// whereas our cluster operator instance is called "authentication" (there is no OR support)
	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, resync)

	resourceSyncerInformers := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
	)

	operatorClient := &authopclient.OperatorClient{
		authOperatorConfigInformers,
		authConfigClient.OperatorV1(),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		resourceSyncerInformers,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		ctx.EventRecorder,
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
		kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		configClient,
		versionGetter,
		ctx.EventRecorder,
		resourceSyncer,
	)

	// oauthClientsController := oauthclientscontroller.NewOAuthClientsController(
	// 	*operatorClient,
	// 	configClient.ConfigV1(),
	// 	configInformers.Config().V1().Authentications(),
	// 	oauthClient.OauthV1(),
	// 	oauthClientInformers.Oauth().V1().OAuthClients(),
	// 	routeClient.RouteV1().Routes("openshift-authentication"),
	// 	routeInformersNamespaced.Route().V1().Routes(),
	// )
	routeController := routecontroller.NewRouteController(
		operatorClient,
		oauthClient.OauthV1().OAuthClients(),
		routeClient.RouteV1(),
		configInformers.Config().V1().Ingresses(),
		routeInformersNamespaced.Route().V1().Routes(),
		map[string][]routecontroller.OAuthClientExpectedRoute{
			"oauth-openshift": []routecontroller.OAuthClientExpectedRoute{
				{
					OAuthClientName: "openshift-browser-client",
					URLFormat:       "https://%s/oauth/token/display",
				},
				{
					OAuthClientName: "openshift-challenging-client",
					URLFormat:       "https://%s/oauth/token/implicit",
				},
			},
		},
		ctx.EventRecorder,
	)
	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		"authentication",
		[]configv1.ObjectReference{
			{Group: operatorv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "authentications", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "infrastructures", Name: "cluster"},
			{Group: configv1.GroupName, Resource: "oauths", Name: "cluster"},
			{Resource: "namespaces", Name: "openshift-config"},
			{Resource: "namespaces", Name: "openshift-config-managed"},
			{Resource: "namespaces", Name: "openshift-authentication"},
			{Resource: "namespaces", Name: "openshift-authentication-operator"},
		},
		configClient.ConfigV1(),
		configInformers.Config().V1().ClusterOperators(),
		operatorClient,
		versionGetter,
		ctx.EventRecorder,
	)

	staleConditions := staleconditions.NewRemoveStaleConditions(
		[]string{
			// in 4.1.0 this was accidentally in the list.  This can be removed in 4.3.
			"Degraded",
		},
		operatorClient,
		ctx.EventRecorder,
	)

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(operatorClient, ctx.EventRecorder)
	logLevelController := loglevel.NewClusterOperatorLoggingController(operatorClient, ctx.EventRecorder)

	routerCertsController := routercerts.NewRouterCertsDomainValidationController(
		operatorClient,
		ctx.EventRecorder,
		configInformers.Config().V1().Ingresses(),
		kubeInformersNamespaced.Core().V1().Secrets(),
		"openshift-authentication",
		"v4-0-config-system-router-certs",
		"oauth-openshift",
	)

	// TODO remove this controller once we support Removed
	managementStateController := management.NewOperatorManagementStateController("authentication", operatorClient, ctx.EventRecorder)
	management.SetOperatorNotRemovable()
	// TODO move to config observers
	// configobserver.NewConfigObserver(...)

	for _, informer := range []interface {
		Start(stopCh <-chan struct{})
	}{
		kubeInformersNamespaced,
		authOperatorConfigInformers,
		routeInformersNamespaced,
		oauthClientInformers,
		configInformers,
		resourceSyncerInformers,
	} {
		informer.Start(ctx.Done())
	}

	for _, controller := range []interface {
		Run(workers int, stopCh <-chan struct{})
	}{
		resourceSyncer,
		clusterOperatorStatus,
		configOverridesController,
		logLevelController,
		routerCertsController,
		routeController,
		managementStateController,
	} {
		go controller.Run(1, ctx.Done())
	}

	go operator.Run(ctx.Done())
	go staleConditions.Run(1, ctx.Done())

	<-ctx.Done()

	return fmt.Errorf("stopped")
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
