package ingressstate

import (
	"context"
	"fmt"
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
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
	endpointsGetter        corev1client.EndpointsGetter
	podsGetter             corev1client.PodsGetter
	targetNamespace        string
	operatorClient         v1helpers.OperatorClient
	authConfigChecker      common.AuthConfigChecker
}

func NewIngressStateController(
	instanceName string,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	endpointsGetter corev1client.EndpointsGetter,
	podsGetter corev1client.PodsGetter,
	operatorClient v1helpers.OperatorClient,
	authConfigChecker common.AuthConfigChecker,
	targetNamespace string,
	recorder events.Recorder,
) factory.Controller {
	c := &ingressStateController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "IngressState"),
		endpointsGetter:        endpointsGetter,
		podsGetter:             podsGetter,
		targetNamespace:        targetNamespace,
		operatorClient:         operatorClient,
		authConfigChecker:      authConfigChecker,
	}

	return factory.New().
		WithInformers(
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Endpoints().Informer(),
		).
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
		// clear all operator conditions
		return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, degradedConditionTypes, nil)
	}

	endpoints, err := c.endpointsGetter.Endpoints(c.targetNamespace).Get(context.TODO(), "oauth-openshift", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Clear the error to allow checkSubset to report degraded because endpoints == nil
		err = nil
	}
	if err != nil {
		return err
	}

	var degradedConditions []operatorv1.OperatorCondition

	subset, subsetCondition, err := subsetWithReadyAddresses(endpoints)
	if err != nil {
		return err
	}
	readyAddresses := subset != nil
	if readyAddresses {
		degradedConditions = checkAddresses(context.TODO(), subset.Addresses, c.checkPodStatus)
	} else {
		// With no ready addresses to check, the subset condition is the only one to report.
		degradedConditions = []operatorv1.OperatorCondition{*subsetCondition}
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
		time.Now().Sub(pod.Status.StartTime.Time) >= maxToleratedPodPendingDuration
	if pendingTooLong {
		result = append(result, fmt.Sprintf("pod %q has been pending for longer than %v", pod.Name, maxToleratedPodPendingDuration))
	}

	return result
}

// subsetWithReadyAddresses returns either a subset or a condition from the
// given endpoints. A subset will be returned if there is a single subset with
// one or more ready addresses, otherwise a condition will be returned. If
// there are more than one subsets, an error will be returned instead of either
// a subset or condition.
func subsetWithReadyAddresses(endpoints *corev1.Endpoints) (*corev1.EndpointSubset, *operatorv1.OperatorCondition, error) {
	// Check for an empty uid to ensure correct error handling when the shared
	// informer returns an empty endpoints resource (instead of nil) when the target
	// endpoints resource has been deleted.
	//
	// TODO(marun) Figure out why the informer is not returning nil when the
	// endpoints resource has been deleted.
	if endpoints == nil || len(endpoints.UID) == 0 {
		return nil, endpointsDegraded("MissingEndpoints", "No endpoints found for oauth-server"), nil
	}
	if len(endpoints.Subsets) == 0 {
		return nil, endpointsDegraded("MissingSubsets", "No subsets found for the endpoints of oauth-server"), nil
	}
	// Assume that the service targets only a single port (and therefore the
	// endpoints have at most one subset) to simplify determination of
	// endpoint health.
	if len(endpoints.Subsets) > 1 {
		return nil, nil, fmt.Errorf("More than one subset found for the endpoints of oauth-server")
	}
	subset := endpoints.Subsets[0]
	// Report degraded if no addresses are ready
	if len(subset.Addresses) == 0 && len(subset.NotReadyAddresses) > 0 {
		msg := fmt.Sprintf("All %d endpoints for oauth-server are reporting 'not ready'", len(subset.NotReadyAddresses))
		return nil, endpointsDegraded("NonReadyEndpoints", msg), nil
	}
	return &subset, nil, nil
}

// Providing these helper functions as arguments to checkAddresses supports
// substituting them in testing.
type checkPodFunc func(ctx context.Context, reference *corev1.ObjectReference) []string

// checkAddresses checks that the provided endpoint's associated pods are healthy,
// and returns the appropriate operator conditions if that is not the case.
func checkAddresses(ctx context.Context, addresses []corev1.EndpointAddress, checkPod checkPodFunc) []operatorv1.OperatorCondition {
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
