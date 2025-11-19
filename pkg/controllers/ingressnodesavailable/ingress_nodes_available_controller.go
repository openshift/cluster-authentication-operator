package ingressnodesavailable

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

var knownConditionNames = sets.NewString(
	"ReadyIngressNodesAvailable",
)

// ingressNodesAvailableController validates that router certs match the ingress domain
type ingressNodesAvailableController struct {
	controllerInstanceName string
	operatorClient         v1helpers.OperatorClient
	ingressLister          operatorv1listers.IngressControllerLister
	nodeLister             corev1listers.NodeLister
	authConfigChecker      common.AuthConfigChecker
}

func NewIngressNodesAvailableController(
	instanceName string,
	operatorClient v1helpers.OperatorClient,
	ingressControllerInformer operatorv1informers.IngressControllerInformer,
	eventRecorder events.Recorder,
	nodeInformer corev1informers.NodeInformer,
	authConfigChecker common.AuthConfigChecker,
) factory.Controller {
	controller := &ingressNodesAvailableController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "IngressNodesAvailable"),
		operatorClient:         operatorClient,
		ingressLister:          ingressControllerInformer.Lister(),
		nodeLister:             nodeInformer.Lister(),
		authConfigChecker:      authConfigChecker,
	}

	return factory.New().
		WithInformers(
			operatorClient.Informer(),
			ingressControllerInformer.Informer(),
			nodeInformer.Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		WithSync(controller.sync).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		ToController(controller.controllerInstanceName, eventRecorder)
}

func countReadyWorkerNodes(nodes []*corev1.Node) int {
	readyNodes := 0
	for _, n := range nodes {
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				readyNodes++
			}
		}
	}
	return readyNodes
}

func (c *ingressNodesAvailableController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		// Server-Side-Apply with an empty operator status for the specific field manager
		// will effectively remove any conditions owned by it since the list type in the
		// API definition is 'map'
		return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, applyoperatorv1.OperatorStatus())
	}

	foundConditions := []operatorv1.OperatorCondition{}

	workers, err := c.nodeLister.List(labels.SelectorFromSet(labels.Set{"node-role.kubernetes.io/worker": ""}))
	if err != nil {
		return err
	}

	// this is best-effort, workers can be tainted and not schedulable, which will result in auth operator to fail
	// as the router need schedulable worker nodes.
	workloadReadyNodes := countReadyWorkerNodes(workers)

	// we don't have any worker nodes schedulable, but we can run clusters that have master nodes schedulable, so we need to check that
	// before going available==false
	var masters []*corev1.Node
	masters, err = c.nodeLister.List(labels.SelectorFromSet(labels.Set{"node-role.kubernetes.io/master": ""}))
	if err != nil {
		return err
	}
	for _, n := range masters {
		isSchedulable := true
		for _, t := range n.Spec.Taints {
			if t.Effect == "NoSchedule" && t.Key == "node-role.kubernetes.io/master" {
				isSchedulable = false
				break
			}
		}
		// only count masters that can schedule workloads (eg. ingress pods)
		if isSchedulable {
			workloadReadyNodes++
		}
	}

	// and finally, check to see if the ingress operator has a node placement policy set that overrides the node selector
	numCustomIngressTargets, err := c.numberOfCustomIngressTargets(ctx, syncCtx)
	if err != nil {
		return err
	}
	workloadReadyNodes += numCustomIngressTargets

	if workloadReadyNodes == 0 {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "ReadyIngressNodesAvailable",
			Status: operatorv1.ConditionFalse,
			Reason: "NoReadyIngressNodes",
			Message: fmt.Sprintf(
				"Authentication requires functional ingress which requires at least one schedulable and ready node. Got %d worker nodes, %d master nodes, %d custom target nodes (none are schedulable or ready for ingress pods).",
				len(workers),
				len(masters),
				numCustomIngressTargets,
			),
		})
	}

	return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, knownConditionNames, foundConditions)
}

func (c *ingressNodesAvailableController) numberOfCustomIngressTargets(ctx context.Context, syncCtx factory.SyncContext) (int, error) {
	ingressControllerConfig, err := c.ingressLister.IngressControllers("openshift-ingress-operator").Get("default")
	switch {
	case errors.IsNotFound(err):
		// do nothing, we have no worker nodes and it should fail the condition
		return 0, nil
	case err != nil:
		return 0, err // return and retry
	default:
		// more computation to do
	}

	// let's check to see if we have special node placement
	if ingressControllerConfig.Spec.NodePlacement == nil || ingressControllerConfig.Spec.NodePlacement.NodeSelector == nil {
		return 0, nil
	}
	nodeSelector, err := metav1.LabelSelectorAsMap(ingressControllerConfig.Spec.NodePlacement.NodeSelector)
	if err != nil {
		return 0, nil // if the node selector doesn't parse properly, then we know that we have zero nodes matching
	}

	ingressTargets, err := c.nodeLister.List(labels.SelectorFromSet(nodeSelector))
	if err != nil {
		return 0, err // return and retry
	}
	return len(ingressTargets), nil
}
