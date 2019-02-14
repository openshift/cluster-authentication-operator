package operator

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/controller"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
)

const resync = 20 * time.Minute

var oldKubeAPIServerOperatorConfigGVR = schema.GroupVersionResource{
	Group:    "kubeapiserver.operator.openshift.io",
	Version:  "v1alpha1",
	Resource: "kubeapiserveroperatorconfigs",
}
var kubeAPIServerOperatorConfigGVR = schema.GroupVersionResource{
	Group:    "operator.openshift.io",
	Version:  "v1",
	Resource: "kubeapiservers",
}
var infrastructureConfigGVR = schema.GroupVersionResource{
	Group:    "config.openshift.io",
	Version:  "v1",
	Resource: "infrastructures",
}

func RunOperator(ctx *controllercmd.ControllerContext) error {
	dynamicClient, err := dynamic.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	oldKubeAPIServerOperatorConfig := dynamicClient.Resource(oldKubeAPIServerOperatorConfigGVR)
	oldKubeAPIServerOperatorConfigInformer := dynamicInformer(oldKubeAPIServerOperatorConfig)
	kubeAPIServerOperatorConfig := dynamicClient.Resource(kubeAPIServerOperatorConfigGVR)
	kubeAPIServerOperatorConfigInformer := dynamicInformer(kubeAPIServerOperatorConfig)
	infrastructureConfig := dynamicClient.Resource(infrastructureConfigGVR)
	infrastructureConfigInformer := dynamicInformer(infrastructureConfig)

	operator := NewOsinOperator(
		oldKubeAPIServerOperatorConfigInformer,
		oldKubeAPIServerOperatorConfig,
		kubeAPIServerOperatorConfigInformer,
		kubeAPIServerOperatorConfig,
		infrastructureConfigInformer,
		infrastructureConfig,
	)

	go oldKubeAPIServerOperatorConfigInformer.Informer().Run(ctx.Context.Done())
	go kubeAPIServerOperatorConfigInformer.Informer().Run(ctx.Context.Done())
	go infrastructureConfigInformer.Informer().Run(ctx.Context.Done())

	go operator.Run(ctx.Context.Done())

	<-ctx.Context.Done()

	return fmt.Errorf("stopped")
}

func dynamicInformer(resource dynamic.ResourceInterface) controller.InformerGetter {
	lw := &cache.ListWatch{
		ListFunc: func(opts v1.ListOptions) (runtime.Object, error) {
			return resource.List(opts)
		},
		WatchFunc: func(opts v1.ListOptions) (watch.Interface, error) {
			return resource.Watch(opts)
		},
	}
	informer := cache.NewSharedIndexInformer(lw, &unstructured.Unstructured{}, resync, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	return &toInformerGetter{informer: informer}
}

type toInformerGetter struct {
	informer cache.SharedIndexInformer
}

func (g *toInformerGetter) Informer() cache.SharedIndexInformer {
	return g.informer
}
