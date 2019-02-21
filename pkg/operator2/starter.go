package operator2

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	authopclient "github.com/openshift/client-go/operator/clientset/versioned"
	authopinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
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

	resourceSyncerInformers := v1helpers.NewKubeInformersForNamespaces(kubeClient, targetName, userConfigNamespace)

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient{}, // TODO fix
		resourceSyncerInformers,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), resourceSyncerInformers),
		ctx.EventRecorder,
	)

	operator := NewAuthenticationOperator(
		authOperatorConfigInformers.Operator().V1().Authentications(),
		authConfigClient.OperatorV1(),
		kubeInformersNamespaced,
		kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		configClient,
		ctx.EventRecorder,
		resourceSyncer,
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

	<-ctx.Done()

	return fmt.Errorf("stopped")
}

func singleNameListOptions(name string) func(opts *v1.ListOptions) {
	return func(opts *v1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}

// temp hack since I do not care about this right now
type operatorClient struct{}

func (operatorClient) Informer() cache.SharedIndexInformer {
	return fakeInformer{}
}

func (operatorClient) GetOperatorState() (spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, resourceVersion string, err error) {
	return &operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, "", nil
}

func (operatorClient) UpdateOperatorSpec(string, *operatorv1.OperatorSpec) (spec *operatorv1.OperatorSpec, resourceVersion string, err error) {
	return nil, "", nil
}

func (operatorClient) UpdateOperatorStatus(string, *operatorv1.OperatorStatus) (status *operatorv1.OperatorStatus, err error) {
	return nil, nil
}

type fakeInformer struct {
	cache.SharedIndexInformer // panics if anything other than AddEventHandler gets called
}

func (fakeInformer) AddEventHandler(_ cache.ResourceEventHandler) {}
