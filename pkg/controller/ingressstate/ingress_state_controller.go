package ingressstate

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const ingressStateControllerWorkQueueKey = "key"

type IngressStateController struct {
	endpointsGetter corev1client.EndpointsGetter
	podGetter       corev1client.PodsGetter
	queue           workqueue.RateLimitingInterface
	cachesToSync    []cache.InformerSynced
	targetNamespace string
	operatorClient  v1helpers.OperatorClient
	eventRecorder   events.Recorder
}

func NewIngressStateController(kubeInformersForTargetNamespace informers.SharedInformerFactory,
	endpointsGetter corev1client.EndpointsGetter,
	podsGetter corev1client.PodsGetter,
	operatorClient v1helpers.OperatorClient,
	targetNamespace string,
	recorder events.Recorder,
) *IngressStateController {
	c := &IngressStateController{
		endpointsGetter: endpointsGetter,
		podGetter:       podsGetter,
		targetNamespace: targetNamespace,
		operatorClient:  operatorClient,
		eventRecorder:   recorder.WithComponentSuffix("ingress-state-controller"),
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "IngressStateController"),
	}

	c.cachesToSync = append(c.cachesToSync, kubeInformersForTargetNamespace.Core().V1().Pods().Informer().HasSynced)
	c.cachesToSync = append(c.cachesToSync, kubeInformersForTargetNamespace.Core().V1().Endpoints().Informer().HasSynced)

	kubeInformersForTargetNamespace.Core().V1().Pods().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForTargetNamespace.Core().V1().Endpoints().Informer().AddEventHandler(c.eventHandler())

	return c
}

func (c *IngressStateController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(ingressStateControllerWorkQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(ingressStateControllerWorkQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(ingressStateControllerWorkQueueKey) },
	}
}

// checkPodStatus will check the target pod container status and return list of possible problems.
func (c *IngressStateController) checkPodStatus(reference *corev1.ObjectReference) []string {
	pod, err := c.podGetter.Pods(reference.Namespace).Get(reference.Name, metav1.GetOptions{})
	if err != nil {
		return []string{fmt.Sprintf("error getting pod %q: %v", reference.Name, err)}
	}
	result := []string{}
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.Ready && containerStatus.State.Running != nil {
			continue
		}
		if terminated := containerStatus.State.Terminated; terminated != nil {
			result = append(result, fmt.Sprintf("pod %q container %q terminated with %q", pod.Name, containerStatus.Name, terminated.Message))
		}
		if containerStatus.RestartCount > 1 {
			result = append(result, fmt.Sprintf("pod %q container %q restarted %d times", pod.Name, containerStatus.Name, containerStatus.RestartCount))
		}
		// TODO: Add more here, like we can detect "pending" pods
	}
	return result
}

// checkEndpointHealthz will check the health of given https://endpointIP:6443/healthz
// TODO: this is insecure for now, but enough to tell us if we can get through
func (c *IngressStateController) checkEndpointHealthz(endpointIP string) error {
	// TODO: consider making this secure, however it will mean wiring the trust which must match the same trust as ingress controller
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	response, err := http.Get(fmt.Sprintf("https://%s:6443/healthz", endpointIP))
	if err != nil {
		reportedError := err
		if response != nil {
			reportedError = fmt.Errorf("status:%q, body: %q, error: %v", response.Status, response.Body, reportedError)
		}
		return reportedError
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status:%q, body: %q", response.Status, response.Body)
	}
	return nil
}

// degradedConditionNames lists all conditions that this controller manage
var degradedConditionNames = []string{
	"IngressStateEndpointsDegraded",
	"IngressStatePodsDegraded",
}

func (c *IngressStateController) sync() error {
	foundConditions := []operatorv1.OperatorCondition{}

	endpoint, err := c.endpointsGetter.Endpoints(c.targetNamespace).Get("oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return err
	}

	if len(endpoint.Subsets) == 0 {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:    "IngressStateEndpointsDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "ZeroEndpointsSubsets",
			Message: "No endpoints found for oauth-server",
		})
	}

	for _, subset := range endpoint.Subsets {
		// If endpoint does not have any ready addresses, only not-ready, report it as IngressStateEndpointsDegraded
		if len(subset.Addresses) == 0 && len(subset.NotReadyAddresses) > 0 {
			foundConditions = append(foundConditions, operatorv1.OperatorCondition{
				Type:    "IngressStateEndpointsDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "NonReadyEndpoints",
				Message: "No ready endpoints found for oauth-server",
			})
			continue
		}

		nonHealthyEndpoints := []string{}
		nonHealthyPods := []string{}
		for _, address := range subset.Addresses {
			// Perform insecure GET on the endpoint IP to check if we can pass trough, if we can't the ingress will neither
			// and we should report degraded.
			if err := c.checkEndpointHealthz(address.IP); err != nil {
				nonHealthyEndpoints = append(nonHealthyEndpoints, fmt.Sprintf("%s:%v", address.IP, err))
			}

			if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
				nonHealthyPods = c.checkPodStatus(address.TargetRef)
			}
		}

		// we should tolerate one endpoint that is terminating during upgrade
		if len(nonHealthyEndpoints) > 1 {
			foundConditions = append(foundConditions, operatorv1.OperatorCondition{
				Type:    "IngressStateEndpointsDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "NonHealthyEndpoints",
				Message: fmt.Sprintf("Non-healthy endpoints found: %s", strings.Join(nonHealthyEndpoints, ",")),
			})
		}

		// we should tolerate one pod that is terminating during upgrade
		if len(nonHealthyPods) > 1 {
			foundConditions = append(foundConditions, operatorv1.OperatorCondition{
				Type:    "IngressStatePodsDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "NonHealthyPods",
				Message: fmt.Sprintf("Non-healthy pods found: %s", strings.Join(nonHealthyPods, ",")),
			})
		}
	}

	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}

	// check the supported degraded foundConditions and check if any pending pod matching them.
	for _, degradedConditionName := range degradedConditionNames {
		// clean up existing foundConditions
		updatedCondition := operatorv1.OperatorCondition{
			Type:   degradedConditionName,
			Status: operatorv1.ConditionFalse,
		}
		if condition := v1helpers.FindOperatorCondition(foundConditions, degradedConditionName); condition != nil {
			updatedCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(updatedCondition))
	}

	if _, _, err := v1helpers.UpdateStatus(c.operatorClient, updateConditionFuncs...); err != nil {
		return err
	}

	return nil
}

// Run starts the kube-apiserver and blocks until stopCh is closed.
func (c *IngressStateController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting IngressStateController")
	defer klog.Infof("Shutting down IngressStateController")
	if !cache.WaitForCacheSync(stopCh, c.cachesToSync...) {
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	// add time based trigger
	go wait.Until(func() { c.queue.Add(ingressStateControllerWorkQueueKey) }, time.Minute, stopCh)

	<-stopCh
}

func (c *IngressStateController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *IngressStateController) processNextWorkItem() bool {
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
