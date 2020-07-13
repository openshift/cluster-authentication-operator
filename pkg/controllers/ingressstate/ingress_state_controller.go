package ingressstate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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
	endpointsGetter corev1client.EndpointsGetter
	podsGetter      corev1client.PodsGetter
	targetNamespace string
	operatorClient  v1helpers.OperatorClient
}

func NewIngressStateController(kubeInformersForTargetNamespace informers.SharedInformerFactory,
	endpointsGetter corev1client.EndpointsGetter,
	podsGetter corev1client.PodsGetter,
	operatorClient v1helpers.OperatorClient,
	targetNamespace string,
	recorder events.Recorder,
) factory.Controller {
	c := &ingressStateController{
		endpointsGetter: endpointsGetter,
		podsGetter:      podsGetter,
		targetNamespace: targetNamespace,
		operatorClient:  operatorClient,
	}

	return factory.New().
		WithInformers(
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Endpoints().Informer(),
		).
		WithSync(c.sync).
		ResyncEvery(30*time.Second).
		ToController("IngressStateController", recorder.WithComponentSuffix("ingress-state-controller"))
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
		serviceCA, err := loadServiceCA()
		if err != nil {
			return err
		}
		degradedConditions = checkAddresses(context.TODO(), subset.Addresses, c.checkPodStatus, func(endpointIP string) error {
			return checkEndpointHealthz(endpointIP, serviceCA)
		})
	} else {
		// With no ready addresses to check, the subset condition is the only one to report.
		degradedConditions = []operatorv1.OperatorCondition{*subsetCondition}
	}

	return common.UpdateControllerConditions(c.operatorClient, degradedConditionTypes, degradedConditions)
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

// loadServiceCA reads the service ca bundle from disk to a cert pool.
// TODO(marun) Consider caching the bundle or using a file observer.
func loadServiceCA() (*x509.CertPool, error) {
	bundlePath := "/var/run/configmaps/service-ca-bundle/service-ca.crt"
	bundlePEM, err := ioutil.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("error reading service ca bundle: %v", err)
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(bundlePEM)
	if !ok {
		return nil, fmt.Errorf("no certificates could be parsed from the service ca bundle")
	}
	return roots, nil
}

// checkEndpointHealthz will check the health of given https://endpointIP:6443/healthz
func checkEndpointHealthz(endpointIP string, rootCAs *x509.CertPool) error {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
				// Specify a host name allowed by the serving cert of the
				// endpoints to ensure that TLS validates succesfully. The
				// serving cert the endpoint uses does not include IP SANs
				// so accessing the endpoint via IP would otherwise result
				// in validation failure.
				ServerName: "oauth-openshift.openshift-authentication.svc",
			},
		},
	}
	url := fmt.Sprintf("https://%s/healthz", net.JoinHostPort(endpointIP, "6443"))
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("status:%q, body: %q", response.Status, respBody)
	}
	return nil
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
type checkEndpointsFunc func(endpointIP string) error

// checkAddresses checks that the provided endpoint addresses are reachable,
// that their associated pods are healthy, and returns the appropriate operator
// conditions if that is not the case.
func checkAddresses(ctx context.Context, addresses []corev1.EndpointAddress, checkPod checkPodFunc, checkEndpoints checkEndpointsFunc) []operatorv1.OperatorCondition {
	unhealthyAddresses := []string{}
	podMessages := map[string][]string{}
	unhealthyPodCount := 0
	for _, address := range addresses {
		if err := checkEndpoints(address.IP); err != nil {
			unhealthyAddresses = append(unhealthyAddresses, fmt.Sprintf("%s:%v", address.IP, err))
		}
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

	// Tolerate a single unhealthy endpoint to allow for termination during upgrade
	if len(unhealthyAddresses) > 1 {
		msg := fmt.Sprintf("Unhealthy addresses found: %s", strings.Join(unhealthyAddresses, ","))
		conditions = append(conditions, *endpointsDegraded("UnhealthyAddresses", msg))
	}

	// Tolerate a single unhealthy pod to allow for termination during upgrade
	if unhealthyPodCount > 1 {
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
