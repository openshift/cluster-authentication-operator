package workload

import (
	"context"
	"fmt"
	operatorv1 "github.com/openshift/api/operator/v1"
	openshiftconfigclientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	clusteroperatorv1helpers "github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"time"
)

const (
	workQueueKey              = "key"
	workloadDegradedCondition = "WorkloadDegraded"
)

// syncFunc a function that will be used for delegation. It should bring the desired workload into operation.
type syncFunc func() (*appsv1.DaemonSet, []error)

// Controller is a generic workload controller that deals with DaemonSet resource.
// Callers must provide a sync function for delegation. It should bring the desired workload into operation.
// The returned state along with errors will be converted into conditions and persisted in the status field.
type Controller struct {
	name              string
	operatorNamespace string
	targetNamespace   string

	operatorClient               v1helpers.OperatorClient
	kubeClient                   kubernetes.Interface
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface
	syncFn                       syncFunc

	queue              workqueue.RateLimitingInterface
	eventRecorder      events.Recorder
	versionRecorder    status.VersionGetter
	preRunCachesSynced []cache.InformerSynced
}

// NewController creates a brand new Controller instance.
//
// the "name" param will be used to set conditions in the status field. It will be suffixed with "WorkloadCtrl",
// so it can end up in the condition in the form of "OAuthAPIWorkloadCtrlDaemonSetAvailable"
//
// the "operatorNamespace" is used to set "version-mapping" in the correct namespace
//
// the "targetNamespace" represent the namespace for the managed resource (DaemonSet)
func NewController(name, operatorNamespace, targetNamespace string,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	syncFn syncFunc,
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface,
	eventRecorder events.Recorder,
	versionRecorder status.VersionGetter) *Controller {
	controllerRef := &Controller{
		operatorNamespace:            operatorNamespace,
		name:                         fmt.Sprintf("%sWorkloadCtrl", name), // ends up being OAuthAPIWorkloadCtrl
		targetNamespace:              targetNamespace,
		operatorClient:               operatorClient,
		kubeClient:                   kubeClient,
		syncFn:                       syncFn,
		openshiftClusterConfigClient: openshiftClusterConfigClient,
		eventRecorder:                eventRecorder.WithComponentSuffix("workload-controller"),
		versionRecorder:              versionRecorder,
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), name),
	}

	return controllerRef
}

func (c *Controller) sync() error {
	operatorSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	if run, err := c.shouldSync(operatorSpec); !run {
		return err
	}

	if fulfilled, err := c.preconditionFulfilled(operatorSpec); !fulfilled {
		return err
	}

	workload, errs := c.syncFn()

	return c.updateOperatorStatus(workload, errs)
}

// Run starts workload controller and blocks until stopCh is closed.
// Note that setting workers doesn't have any effect, the controller is single-threaded.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", c.name)
	defer klog.Infof("Shutting down %s", c.name)
	if !cache.WaitForCacheSync(ctx.Done(), c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
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

// AddInformer queues the given informer to check spec, status and managed resources
func (c *Controller) AddInformer(informer cache.SharedIndexInformer) *Controller {
	informer.AddEventHandler(c.eventHandler())
	c.preRunCachesSynced = append(c.preRunCachesSynced, informer.HasSynced)
	return c
}

// AddNamespaceInformer queues the given ns informer for the targetNamespace
func (c *Controller) AddNamespaceInformer(informer cache.SharedIndexInformer) *Controller {
	interestingNamespaces := sets.NewString(c.targetNamespace)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if interestingNamespaces.Has(ns.Name) {
				c.queue.Add(workQueueKey)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			ns, ok := old.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if interestingNamespaces.Has(ns.Name) {
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
			if interestingNamespaces.Has(ns.Name) {
				c.queue.Add(workQueueKey)
			}
		},
	})
	c.preRunCachesSynced = append(c.preRunCachesSynced, informer.HasSynced)

	return c
}

func (c *Controller) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workQueueKey) },
	}
}

// shouldSync checks ManagementState to determine if we can run this operator, probably set by a cluster administrator.
func (c *Controller) shouldSync(operatorSpec *operatorv1.OperatorSpec) (bool, error) {
	switch operatorSpec.ManagementState {
	case operatorv1.Managed:
		return true, nil
	case operatorv1.Unmanaged:
		return false, nil
	case operatorv1.Removed:
		if err := c.kubeClient.CoreV1().Namespaces().Delete(c.targetNamespace, nil); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		return false, nil
	default:
		c.eventRecorder.Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorSpec.ManagementState)
		return false, nil
	}
}

// preconditionFulfilled checks if kube-apiserver is present and available
func (c *Controller) preconditionFulfilled(operatorSpec *operatorv1.OperatorSpec) (bool, error) {
	kubeAPIServerClusterOperator, err := c.openshiftClusterConfigClient.Get("kube-apiserver", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		message := "clusteroperator/kube-apiserver not found"
		c.eventRecorder.Warning("PrereqNotReady", message)
		return false, fmt.Errorf(message)
	}
	if err != nil {
		return false, err
	}
	if !clusteroperatorv1helpers.IsStatusConditionTrue(kubeAPIServerClusterOperator.Status.Conditions, "Available") {
		message := fmt.Sprintf("clusteroperator/%s is not Available", kubeAPIServerClusterOperator.Name)
		c.eventRecorder.Warning("PrereqNotReady", message)
		return false, fmt.Errorf(message)
	}

	return true, nil
}

// updateOperatorStatus updates the status based on the actual workload and errors that might have occurred during synchronization.
func (c *Controller) updateOperatorStatus(workload *appsv1.DaemonSet, errs []error) error {
	if errs == nil {
		errs = []error{}
	}

	dsAvailableCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDaemonSet%s", c.name, operatorv1.OperatorStatusTypeAvailable),
		Status: operatorv1.ConditionTrue,
	}

	workloadDegradedCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%s%s", c.name, workloadDegradedCondition),
		Status: operatorv1.ConditionFalse,
	}

	dsDegradedCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%ssDaemonSetDegraded", c.name),
		Status: operatorv1.ConditionFalse,
	}

	dsProgressingCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%ssDaemonSet%s", c.name, operatorv1.OperatorStatusTypeProgressing),
		Status: operatorv1.ConditionFalse,
	}

	if len(errs) > 0 {
		message := ""
		for _, err := range errs {
			message = message + err.Error() + "\n"
		}
		workloadDegradedCondition.Status = operatorv1.ConditionTrue
		workloadDegradedCondition.Reason = "SyncError"
		workloadDegradedCondition.Message = message
	} else {
		workloadDegradedCondition.Status = operatorv1.ConditionFalse
	}

	if workload == nil {
		message := fmt.Sprintf("daemonset/%s: could not be retrieved", c.targetNamespace)
		dsAvailableCondition.Status = operatorv1.ConditionFalse
		dsAvailableCondition.Reason = "NoDaemon"
		dsAvailableCondition.Message = message

		dsProgressingCondition.Status = operatorv1.ConditionTrue
		dsProgressingCondition.Reason = "NoDaemon"
		dsProgressingCondition.Message = message

		dsDegradedCondition.Status = operatorv1.ConditionTrue
		dsDegradedCondition.Reason = "NoDaemon"
		dsDegradedCondition.Message = message

		if _, _, updateError := v1helpers.UpdateStatus(c.operatorClient,
			v1helpers.UpdateConditionFn(dsAvailableCondition),
			v1helpers.UpdateConditionFn(workloadDegradedCondition),
			v1helpers.UpdateConditionFn(dsDegradedCondition),
			v1helpers.UpdateConditionFn(dsProgressingCondition)); updateError != nil {
			return updateError
		}
		return errors.NewAggregate(errs)
	}

	if workload.Status.NumberAvailable == 0 {
		dsAvailableCondition.Status = operatorv1.ConditionFalse
		dsAvailableCondition.Reason = "NoPod"
		dsAvailableCondition.Message = fmt.Sprintf("no %s.%s daemon pods available on any node.", workload.Name, c.targetNamespace)
	} else {
		dsAvailableCondition.Status = operatorv1.ConditionTrue
		dsAvailableCondition.Reason = "AsExpected"
	}

	// If the daemonset is up to date, then we are no longer progressing
	daemonSetAtHighestGeneration := workload.ObjectMeta.Generation == workload.Status.ObservedGeneration
	if !daemonSetAtHighestGeneration {
		dsProgressingCondition.Status = operatorv1.ConditionTrue
		dsProgressingCondition.Reason = "NewGeneration"
		dsProgressingCondition.Message = fmt.Sprintf("daemonset/%s.%s: observed generation is %d, desired generation is %d.", workload.Name, c.targetNamespace, workload.Status.ObservedGeneration, workload.ObjectMeta.Generation)
	} else {
		dsProgressingCondition.Status = operatorv1.ConditionFalse
		dsProgressingCondition.Reason = "AsExpected"
	}

	daemonSetHasAllPodsAvailable := workload.Status.NumberAvailable == workload.Status.DesiredNumberScheduled
	if !daemonSetHasAllPodsAvailable {
		numNonAvailablePods := workload.Status.DesiredNumberScheduled - workload.Status.NumberAvailable
		dsDegradedCondition.Status = operatorv1.ConditionTrue
		dsDegradedCondition.Reason = "UnavailablePod"
		dsDegradedCondition.Message = fmt.Sprintf("%v of %v requested instances are unavailable for %s.%s", numNonAvailablePods, workload.Status.DesiredNumberScheduled, workload.Name, c.targetNamespace)
	} else {
		dsDegradedCondition.Status = operatorv1.ConditionFalse
		dsDegradedCondition.Reason = "AsExpected"
	}

	// if the daemonset is all available and at the expected generation, then update the version to the latest
	daemonSetHasAllPodsUpdated := workload.Status.UpdatedNumberScheduled == workload.Status.DesiredNumberScheduled
	if daemonSetAtHighestGeneration && daemonSetHasAllPodsAvailable && daemonSetHasAllPodsUpdated {
		// we have the actual daemonset and we need the pull spec
		operandVersion := status.VersionForOperand(
			c.operatorNamespace,
			workload.Spec.Template.Spec.Containers[0].Image,
			c.kubeClient.CoreV1(),
			c.eventRecorder)
		c.versionRecorder.SetVersion(fmt.Sprintf("%s", workload.Name), operandVersion)
	}

	updateGenerationFn := func(newStatus *operatorv1.OperatorStatus) error {
		resourcemerge.SetDaemonSetGeneration(&newStatus.Generations, workload)
		return nil
	}

	if _, _, updateError := v1helpers.UpdateStatus(c.operatorClient,
		v1helpers.UpdateConditionFn(dsAvailableCondition),
		v1helpers.UpdateConditionFn(workloadDegradedCondition),
		v1helpers.UpdateConditionFn(dsDegradedCondition),
		v1helpers.UpdateConditionFn(dsProgressingCondition),
		updateGenerationFn); updateError != nil {
		return updateError
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	return nil
}
