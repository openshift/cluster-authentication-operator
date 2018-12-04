package operator

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
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

	// TODO this is hack to get around no watch for kubeAPIServerOperatorConfig
	const resync = time.Minute

	kubeInformersNamespaced := informers.NewSharedInformerFactoryWithOptions(kubeClient, resync,
		informers.WithNamespace(targetNamespaceName),
		informers.WithTweakListOptions(func(opts *v1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", targetConfigMap).String()
		}),
	)

	operator := NewOsinOperator(
		kubeInformersNamespaced.Core().V1().ConfigMaps(),
		kubeClient.CoreV1(),
		dynamicClient,
	)

	kubeInformersNamespaced.Start(ctx.StopCh)

	go operator.Run(ctx.StopCh)

	<-ctx.StopCh

	return fmt.Errorf("stopped")
}
