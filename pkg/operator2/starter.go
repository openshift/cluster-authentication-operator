package operator2

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	osinv1alpha1 "github.com/openshift/cluster-osin-operator/pkg/apis/osin/v1alpha1"
	osinclient "github.com/openshift/cluster-osin-operator/pkg/generated/clientset/versioned"
	osininformer "github.com/openshift/cluster-osin-operator/pkg/generated/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	resync = 20 * time.Minute

	osinResource = `
apiVersion: osin.openshift.io/v1alpha1
kind: Osin
metadata:
  name: openshift-osin
  namespace: openshift-osin
spec:
  managementState: Managed
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

	osinClient, err := osinclient.NewForConfig(ctx.KubeConfig)
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

	osinInformersNamespaced := osininformer.NewSharedInformerFactoryWithOptions(osinClient, resync,
		osininformer.WithNamespace(targetName),
		osininformer.WithTweakListOptions(singleNameListOptions(targetName)),
	)

	routeInformersNamespaced := routeinformer.NewSharedInformerFactoryWithOptions(routeClient, resync,
		routeinformer.WithNamespace(targetName),
		routeinformer.WithTweakListOptions(singleNameListOptions(targetName)),
	)

	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, resync,
		configinformer.WithTweakListOptions(singleNameListOptions(configName)),
	)

	v1helpers.EnsureOperatorConfigExists(
		dynamicClient,
		[]byte(osinResource),
		osinv1alpha1.GroupVersion.WithResource("osins"),
	)

	operator := NewOsinOperator(
		osinInformersNamespaced.Osin().V1alpha1().Osins(),
		osinClient.OsinV1alpha1(),
		kubeInformersNamespaced,
		kubeClient,
		routeInformersNamespaced.Route().V1().Routes(),
		routeClient.RouteV1(),
		configInformers,
		configClient,
		recorder{}, // TODO ctx.EventRecorder,
	)

	for _, informer := range []interface {
		Start(stopCh <-chan struct{})
	}{
		kubeInformersNamespaced,
		osinInformersNamespaced,
		routeInformersNamespaced,
		configInformers,
	} {
		informer.Start(ctx.StopCh)
	}

	go operator.Run(ctx.StopCh)

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
