package ingressnodesavailable

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var knownConditionNames = sets.NewString(
	"ReadyIngressNodesAvailable",
)

// ingressNodesAvailableController validates that router certs match the ingress domain
type ingressNodesAvailableController struct {
	operatorClient v1helpers.OperatorClient
	nodeLister     corev1listers.NodeLister
}

func NewIngressNodesAvailableController(
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
	nodeInformer corev1informers.NodeInformer,
) factory.Controller {
	controller := &ingressNodesAvailableController{
		operatorClient: operatorClient,
		nodeLister:     nodeInformer.Lister(),
	}

	return factory.New().
		WithInformers(
			operatorClient.Informer(),
			nodeInformer.Informer(),
		).
		WithSync(controller.sync).
		ResyncEvery(1*time.Minute).
		ToController("IngressNodesAvailableController", eventRecorder)
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

	if workloadReadyNodes == 0 {
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:   "ReadyIngressNodesAvailable",
			Status: operatorv1.ConditionFalse,
			Reason: "NoReadyIngressNodes",
			Message: fmt.Sprintf("Authentication requires functional ingress which requires at least one schedulable and ready node. Got %d worker nodes and %d master nodes (none are schedulable or ready for ingress pods).",
				len(workers), len(masters)),
		})
	}

	return common.UpdateControllerConditions(c.operatorClient, knownConditionNames, foundConditions)
}
