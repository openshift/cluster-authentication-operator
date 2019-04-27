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
	authopclient "github.com/openshift/client-go/operator/clientset/versioned"
	authopinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
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

	authConfigClient, err := authopclient.NewForConfig(ctx.KubeConfig)
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
		informers.WithNamespace(targetNamespace),
	)

	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authConfigClient, resync,
		authopinformer.WithTweakListOptions(singleNameListOptions(globalConfigName)),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace(targetNamespace),
		routeinformer.WithTweakListOptions(singleNameListOptions(targetName)),
	)

	// do not use WithTweakListOptions here as top level configs are all called "cluster"
	// whereas our cluster operator instance is called "authentication" (there is no OR support)
	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, resync)

	resourceSyncerInformers := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		targetNamespace,
		userConfigNamespace,
		managedConfigNamespace,
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
		ctx.EventRecorder,
	)

	// add syncing for the OAuth metadata ConfigMap
	if err := resourceSyncer.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: managedConfigNamespace, Name: targetName},
		resourcesynccontroller.ResourceLocation{Namespace: targetNamespace, Name: oauthMetadataName},
	); err != nil {
		return err
	}

	// add syncing for router certs for all cluster ingresses
	if err := resourceSyncer.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: targetNamespace, Name: routerCertsLocalName},
		resourcesynccontroller.ResourceLocation{Namespace: managedConfigNamespace, Name: routerCertsSharedName},
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

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		clusterOperatorName,
		[]configv1.ObjectReference{
			{Group: operatorv1.GroupName, Resource: "authentications", Name: globalConfigName},
			{Group: configv1.GroupName, Resource: "authentications", Name: globalConfigName},
			{Group: configv1.GroupName, Resource: "infrastructures", Name: globalConfigName},
			{Group: configv1.GroupName, Resource: "oauths", Name: globalConfigName},
			{Resource: "namespaces", Name: userConfigNamespace},
			{Resource: "namespaces", Name: managedConfigNamespace},
			{Resource: "namespaces", Name: targetNamespace},
			{Resource: "namespaces", Name: targetNameOperator},
		},
		configClient.ConfigV1(),
		configInformers.Config().V1().ClusterOperators(),
		operatorClient,
		versionGetter,
		ctx.EventRecorder,
	)

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

	go operator.Run(ctx.Done())
	go resourceSyncer.Run(1, ctx.Done())
	go clusterOperatorStatus.Run(1, ctx.Done())

	<-ctx.Done()

	return fmt.Errorf("stopped")
}

func singleNameListOptions(name string) func(opts *metav1.ListOptions) {
	return func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}
