package operator2

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	authv1alpha1 "github.com/openshift/cluster-osin-operator/pkg/apis/authentication/v1alpha1"
	authopclient "github.com/openshift/cluster-osin-operator/pkg/generated/clientset/versioned"
	authopinformer "github.com/openshift/cluster-osin-operator/pkg/generated/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	resync = 20 * time.Minute

	authConfigResource = `
apiVersion: authentication.operator.openshift.io/v1alpha1
kind: AuthenticationOperatorConfig
metadata:
  name: ` + globalConfigName + `
spec:
  managementState: Paused
`
)

func RunOperator(ctx *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(ctx.KubeConfig)
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

	routeClient, err := routeclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	configClient, err := configclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	kubeInformersNamespaced := informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
		informers.WithNamespace(targetName),
		informers.WithTweakListOptions(singleNameListOptions(targetName)),
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

	v1helpers.EnsureOperatorConfigExists(
		dynamicClient,
		[]byte(authConfigResource),
		authv1alpha1.GroupVersion.WithResource("authenticationoperatorconfigs"),
	)

	resourceSyncerInformers := map[string]informers.SharedInformerFactory{
		targetName: informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
			informers.WithNamespace(targetName), // TODO fix
		),
		userConfigNamespace: informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
			informers.WithNamespace(userConfigNamespace),
		),
	}

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		operatorClient{}, // TODO fix
		resourceSyncerInformers,
		kubeClient,
		recorder{}, // TODO ctx.EventRecorder,
	)

	operator := NewAuthenticationOperator(
		authOperatorConfigInformers.Authentication().V1alpha1().AuthenticationOperatorConfigs(),
		authConfigClient.AuthenticationV1alpha1(),
		kubeInformersNamespaced,
		kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		configClient,
		recorder{}, // TODO ctx.EventRecorder,
		resourceSyncer,
	)

	for _, informer := range []interface {
		Start(stopCh <-chan struct{})
	}{
		kubeInformersNamespaced,
		authOperatorConfigInformers,
		routeInformersNamespaced,
		configInformers,
	} {
		informer.Start(ctx.StopCh)
	}

	for _, informer := range resourceSyncerInformers {
		informer.Start(ctx.StopCh)
	}

	go operator.Run(ctx.StopCh)
	go resourceSyncer.Run(1, ctx.StopCh)

	<-ctx.StopCh

	return fmt.Errorf("stopped")
}

func singleNameListOptions(name string) func(opts *v1.ListOptions) {
	return func(opts *v1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
	}
}

// temp hack until I fix lib-go
type recorder struct{}

func (recorder) Event(reason, message string)                            {}
func (recorder) Eventf(reason, messageFmt string, args ...interface{})   {}
func (recorder) Warning(reason, message string)                          {}
func (recorder) Warningf(reason, messageFmt string, args ...interface{}) {}

// temp hack since I do not care about this right now
type operatorClient struct{}

func (operatorClient) Informer() cache.SharedIndexInformer {
	return fakeInformer{}
}
func (operatorClient) Get() (*operatorv1.OperatorSpec, *operatorv1.StaticPodOperatorStatus, string, error) {
	return &operatorv1.OperatorSpec{}, &operatorv1.StaticPodOperatorStatus{}, "", nil
}
func (operatorClient) UpdateStatus(string, *operatorv1.StaticPodOperatorStatus) (*operatorv1.StaticPodOperatorStatus, error) {
	return nil, nil
}

type fakeInformer struct {
	cache.SharedIndexInformer // panics if anything other than AddEventHandler gets called
}

func (fakeInformer) AddEventHandler(_ cache.ResourceEventHandler) {}
