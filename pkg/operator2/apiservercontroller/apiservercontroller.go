package apiservercontroller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	apiregistrationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"

	openshiftconfigclientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
)

const (
	workQueueKey = "apiservercontroller"
)

type OAuthAPIServerController struct {
	targetImagePullSpec, operatorImagePullSpec string

	versionRecorder status.VersionGetter
	// FIXME: this might needs its own operator type?
	operatorConfigClient    operatorv1client.OpenShiftAPIServersGetter
	openshiftConfigClient   openshiftconfigclientv1.ConfigV1Interface
	kubeClient              kubernetes.Interface
	apiregistrationv1Client apiregistrationv1client.ApiregistrationV1Interface
	eventRecorder           events.Recorder

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

func NewOAuthAPIServerController(
	targetImagePullSpec, operatorImagePullSpec string,
	versionRecorder status.VersionGetter,
	operatorConfigInformer operatorv1informers.OpenShiftAPIServerInformer,
	kubeInformersForOAuthAPIServerNamespace kubeinformers.SharedInformerFactory,
	kubeInformersForEtcdNamespace kubeinformers.SharedInformerFactory,
	kubeInformersForOpenShiftConfigNamespace kubeinformers.SharedInformerFactory,
	apiregistrationInformers apiregistrationinformers.SharedInformerFactory,
	configInformers configinformers.SharedInformerFactory,
	operatorConfigClient operatorv1client.OpenShiftAPIServersGetter,
	openshiftConfigClient openshiftconfigclientv1.ConfigV1Interface,
	kubeClient kubernetes.Interface,
	apiregistrationv1Client apiregistrationv1client.ApiregistrationV1Interface,
	eventRecorder events.Recorder,
) *OAuthAPIServerController {
	c := &OAuthAPIServerController{
		targetImagePullSpec:   targetImagePullSpec,
		operatorImagePullSpec: operatorImagePullSpec,

		versionRecorder:         versionRecorder,
		operatorConfigClient:    operatorConfigClient,
		openshiftConfigClient:   openshiftConfigClient,
		kubeClient:              kubeClient,
		apiregistrationv1Client: apiregistrationv1Client,
		eventRecorder:           eventRecorder.WithComponentSuffix("workload-controller"),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "OpenShiftAPIServerOperator"),
	}

	operatorConfigInformer.Informer().AddEventHandler(c.eventHandler())
	kubeInformersForEtcdNamespace.Core().V1().ConfigMaps().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForEtcdNamespace.Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForOAuthAPIServerNamespace.Core().V1().ConfigMaps().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForOAuthAPIServerNamespace.Core().V1().ServiceAccounts().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForOAuthAPIServerNamespace.Core().V1().Services().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForOAuthAPIServerNamespace.Apps().V1().DaemonSets().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForOpenShiftConfigNamespace.Core().V1().ConfigMaps().Informer().AddEventHandler(c.eventHandler())
	configInformers.Config().V1().Images().Informer().AddEventHandler(c.eventHandler())
	apiregistrationInformers.Apiregistration().V1().APIServices().Informer().AddEventHandler(c.eventHandler())

	// we only watch some namespaces
	kubeInformersForOAuthAPIServerNamespace.Core().V1().Namespaces().Informer().AddEventHandler(c.namespaceEventHandler())

	return c
}

func (c OAuthAPIServerController) sync() error {
	return nil
}

func (c *OAuthAPIServerController) namespaceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if ns.Name == "openshift-apiserver-oauth" {
				c.queue.Add(workQueueKey)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			ns, ok := old.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if ns.Name == "openshift-apiserver-oauth" {
				c.queue.Add(workQueueKey)
			}
		},
		DeleteFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
					return
				}
				ns, ok = tombstone.Obj.(*corev1.Namespace)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Namespace %#v", obj))
					return
				}
			}
			if ns.Name == "openshift-apiserver-oauth" {
				c.queue.Add(workQueueKey)
			}
		},
	}
}

// Run starts the openshift-apiserver and blocks until ctx.Done() is closed.
func (c *OAuthAPIServerController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting OpenShiftAPIServerOperator")
	defer klog.Infof("Shutting down OpenShiftAPIServerOperator")

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
}

func (c *OAuthAPIServerController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *OAuthAPIServerController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// eventHandler queues the operator to check spec and status
func (c *OAuthAPIServerController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workQueueKey) },
	}
}
