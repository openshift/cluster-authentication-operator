package ingressstate

import (
	"context"
	"fmt"
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	discoveryv1client "k8s.io/client-go/kubernetes/typed/discovery/v1"
)

const (
	maxToleratedPodPendingDuration = 5 * time.Minute
)

// degradedConditionTypes contains all conditions that this controller manages
var degradedConditionTypes = sets.NewString(
	"IngressStateEndpointsDegraded",
	"IngressStatePodsDegraded",
)

type ingressStateController struct {
	controllerInstanceName string
	endpointSlicesGetter   discoveryv1client.EndpointSlicesGetter
	podsGetter             corev1client.PodsGetter
	targetNamespace        string
	operatorClient         v1helpers.OperatorClient
	authConfigChecker      common.AuthConfigChecker
}

func NewIngressStateController(
	instanceName string,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	endpointSlicesGetter discoveryv1client.EndpointSlicesGetter,
	podsGetter corev1client.PodsGetter,
	operatorClient v1helpers.OperatorClient,
	authConfigChecker common.AuthConfigChecker,
	targetNamespace string,
	recorder events.Recorder,
) factory.Controller {
	c := &ingressStateController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "IngressState"),
		endpointSlicesGetter:   endpointSlicesGetter,
		podsGetter:             podsGetter,
		targetNamespace:        targetNamespace,
		operatorClient:         operatorClient,
		authConfigChecker:      authConfigChecker,
	}

	return factory.New().
		WithInformers(
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Discovery().V1().EndpointSlices().Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		WithSync(c.sync).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController(c.controllerInstanceName, recorder.WithComponentSuffix("ingress-state-controller"))
}

// checkPodStatus will check the target pod container status and return a list of possible problems.
func (c *ingressStateController) checkPodStatus(ctx context.Context, reference *corev1.ObjectReference) []string {
	pod, err := c.podsGetter.Pods(reference.Namespace).Get(ctx, reference.Name, metav1.GetOptions{})
	if err != nil {
		return []string{fmt.Sprintf("error getting pod %q: %v", reference.Name, err)}
	}
	return unhealthyPodMessages(pod)
}

func (c *ingressStateController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		// Server-Side-Apply with an empty operator status for the specific field manager
		// will effectively remove any conditions owned by it since the list type in the
		// API definition is 'map'
		return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, applyoperatorv1.OperatorStatus())
	}

	sliceList, err := c.endpointSlicesGetter.EndpointSlices(c.targetNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: common.ServiceEndpointSliceSelector("oauth-openshift").String(),
	})
	if err != nil {
		return err
	}

	slices := make([]*discoveryv1.EndpointSlice, 0, len(sliceList.Items))
	for i := range sliceList.Items {
		slices = append(slices, &sliceList.Items[i])
	}

	var degradedConditions []operatorv1.OperatorCondition

	readyAddresses, degradedCondition := readyAddressesOrDegraded(len(slices), common.FlattenServiceEndpoints(slices))
	if degradedCondition != nil {
		// With no ready addresses to check, the degraded condition is the only one to report.
		degradedConditions = []operatorv1.OperatorCondition{*degradedCondition}
	} else {
		degradedConditions = checkAddresses(ctx, readyAddresses, c.checkPodStatus)
	}

	return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, degradedConditionTypes, degradedConditions)
}

// unhealthyPodMessages returns a slice of messages intended to aid in the
// diagnosis of why the endpoint address associated with the pod is not
// healthy.
func unhealthyPodMessages(pod *corev1.Pod) []string {
	result := []string{}
	for _, containerStatus := range pod.Status.ContainerStatuses {
		healthy := containerStatus.Ready && containerStatus.State.Running != nil
		if healthy {
			continue
		}
		if terminated := containerStatus.State.Terminated; terminated != nil {
			result = append(result, fmt.Sprintf("pod %q container %q terminated with %q", pod.Name, containerStatus.Name, terminated.Message))
		}
		if containerStatus.RestartCount > 1 {
			result = append(result, fmt.Sprintf("pod %q container %q restarted %d times", pod.Name, containerStatus.Name, containerStatus.RestartCount))
		}
	}
	pendingTooLong := pod.Status.Phase == corev1.PodPending && pod.Status.StartTime != nil &&
		time.Since(pod.Status.StartTime.Time) >= maxToleratedPodPendingDuration
	if pendingTooLong {
		result = append(result, fmt.Sprintf("pod %q has been pending for longer than %v", pod.Name, maxToleratedPodPendingDuration))
	}

	return result
}

// readyAddressesOrDegraded returns the ready backend addresses of the oauth-server
// service, or a degraded condition describing why none are available. sliceCount
// is the number of EndpointSlices found for the service and endpoints is the
// flattened view of their addresses.
func readyAddressesOrDegraded(sliceCount int, endpoints []common.ServiceEndpoint) ([]common.ServiceEndpoint, *operatorv1.OperatorCondition) {
	if sliceCount == 0 {
		return nil, endpointsDegraded("MissingEndpoints", "No endpoints found for oauth-server")
	}
	if len(endpoints) == 0 {
		return nil, endpointsDegraded("MissingSubsets", "No addresses found in the EndpointSlices of oauth-server")
	}

	var ready []common.ServiceEndpoint
	notReady := 0
	for _, endpoint := range endpoints {
		if endpoint.Ready {
			ready = append(ready, endpoint)
		} else {
			notReady++
		}
	}

	// Report degraded if no addresses are ready
	if len(ready) == 0 {
		msg := fmt.Sprintf("All %d endpoints for oauth-server are reporting 'not ready'", notReady)
		return nil, endpointsDegraded("NonReadyEndpoints", msg)
	}
	return ready, nil
}

// Providing these helper functions as arguments to checkAddresses supports
// substituting them in testing.
type checkPodFunc func(ctx context.Context, reference *corev1.ObjectReference) []string

// checkAddresses checks that the provided endpoint's associated pods are healthy,
// and returns the appropriate operator conditions if that is not the case.
func checkAddresses(ctx context.Context, addresses []common.ServiceEndpoint, checkPod checkPodFunc) []operatorv1.OperatorCondition {
	podMessages := map[string][]string{}
	unhealthyPodCount := 0
	for _, address := range addresses {
		if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
			podName := address.TargetRef.Name
			if _, alreadyChecked := podMessages[podName]; alreadyChecked {
				// A pod only needs to be checked once per sync for any address
				continue
			}
			messages := checkPod(ctx, address.TargetRef)
			if len(messages) > 0 {
				unhealthyPodCount++
			}
			podMessages[podName] = messages
		}
	}

	conditions := []operatorv1.OperatorCondition{}

	if unhealthyPodCount > 0 {
		unhealthyMessages := []string{}
		for _, messages := range podMessages {
			unhealthyMessages = append(unhealthyMessages, messages...)
		}
		conditions = append(conditions, operatorv1.OperatorCondition{
			Type:    "IngressStatePodsDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "UnhealthyPods",
			Message: fmt.Sprintf("Unhealthy pods found: %s", strings.Join(unhealthyMessages, ",")),
		})
	}

	return conditions
}

func endpointsDegraded(reason, message string) *operatorv1.OperatorCondition {
	return &operatorv1.OperatorCondition{
		Type:    "IngressStateEndpointsDegraded",
		Status:  operatorv1.ConditionTrue,
		Reason:  reason,
		Message: message,
	}
}
