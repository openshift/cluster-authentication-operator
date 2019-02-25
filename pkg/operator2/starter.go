package operator2

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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

	defaultOperatorConfig = `
apiVersion: operator.openshift.io/v1
kind: Authentication
metadata:
  name: ` + globalConfigName + `
spec:
  managementState: Managed
`

	// TODO figure out the permanent home for top level CRDs and default CRs
	defaultAuthentication = `
apiVersion: config.openshift.io/v1
kind: Authentication
metadata:
  name: ` + globalConfigName + `
spec:
  type: IntegratedOAuth
`
	defaultOAuth = `
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: ` + globalConfigName + `
spec:
  tokenConfig:
    accessTokenMaxAgeSeconds: 86400
`
)

var customResources = map[schema.GroupVersionResource]string{
	operatorv1.GroupVersion.WithResource("authentications"): defaultOperatorConfig,
	configv1.GroupVersion.WithResource("authentications"):   defaultAuthentication,
	configv1.GroupVersion.WithResource("oauths"):            defaultOAuth,
}

func RunOperator(ctx *controllercmd.ControllerContext) error {
	// protobuf can be used with non custom resources
	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(ctx.KubeConfig)
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
		informers.WithNamespace(targetName),
	)

	authOperatorConfigInformers := authopinformer.NewSharedInformerFactoryWithOptions(authConfigClient, resync,
		authopinformer.WithTweakListOptions(singleNameListOptions(globalConfigName)),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace(targetName),
		routeinformer.WithTweakListOptions(singleNameListOptions(targetName)),
	)

	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, resync,
		configinformer.WithTweakListOptions(singleNameListOptions(globalConfigName)),
	)

	for gvr, resource := range customResources {
		v1helpers.EnsureOperatorConfigExists(dynamicClient, []byte(resource), gvr)
	}

	resourceSyncerInformers := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		targetName,
		userConfigNamespace,
		machineConfigNamespace,
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
		resourcesynccontroller.ResourceLocation{Namespace: machineConfigNamespace, Name: targetName},
		resourcesynccontroller.ResourceLocation{Namespace: targetName, Name: oauthMetadataName},
	); err != nil {
		return err
	}

	// add syncing for router certs for all cluster ingresses
	if err := resourceSyncer.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: targetName, Name: routerCertsLocalName},
		resourcesynccontroller.ResourceLocation{Namespace: machineConfigNamespace, Name: routerCertsSharedName},
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
		ctx.KubeConfig,
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
			{Resource: "namespaces", Name: machineConfigNamespace},
			{Resource: "namespaces", Name: targetName},
			{Resource: "namespaces", Name: targetNameOperator},
		},
		configClient.ConfigV1(),
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
