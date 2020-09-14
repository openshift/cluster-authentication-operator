package common

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelistersv1 "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
)

// DeploymentPodsStatus return detailed information about deployment pods and the containers
// TODO: Move this to library-go
func DeploymentPodsStatus(deployment *appsv1.Deployment, podClient corelistersv1.PodLister) ([]string, error) {
	deploymentPods, err := podClient.Pods(deployment.Namespace).List(labels.SelectorFromSet(deployment.Spec.Template.Labels))
	if err != nil {
		return nil, err
	}
	deploymentPodsStates := []string{}
	for i := range deploymentPods {
		containerStates := []string{}
		for _, c := range append(deploymentPods[i].Status.ContainerStatuses, deploymentPods[i].Status.InitContainerStatuses...) {
			switch {
			case c.State.Running != nil:
				containerStates = append(containerStates, fmt.Sprintf("container %q is running since %s", c.Name, c.State.Running.StartedAt))
			case c.State.Waiting != nil:
				containerStates = append(containerStates, fmt.Sprintf("container %q is waiting: %s - %s", c.Name, c.State.Waiting.Reason, c.State.Waiting.Message))
			case c.State.Terminated != nil:
				containerStates = append(containerStates, fmt.Sprintf("container %q is terminated (recv: %d, exit: %d): %s - %s", c.Name, c.State.Terminated.Signal, c.State.Terminated.ExitCode,
					c.State.Terminated.Reason, c.State.Terminated.Message))
			}
			if c.RestartCount > 0 {
				containerStates = append(containerStates, fmt.Sprintf("container %q restarted %dx times", c.RestartCount, c.Name))
			}
		}
		podConditions := []string{
			fmt.Sprintf("phase=%s", deploymentPods[i].Status.Phase),
		}
		for _, c := range deploymentPods[i].Status.Conditions {
			podConditions = append(podConditions, fmt.Sprintf("%s=%s (%s#%s)", c.Type, c.Status, c.Reason, c.Message))
		}
		deploymentPodsStates = append(deploymentPodsStates, fmt.Sprintf("pod %q is %s (%s)", deploymentPods[i].Name, strings.Join(podConditions, ","), strings.Join(containerStates, ",")))
	}
	return deploymentPodsStates, nil
}

func CheckDeploymentReady(deployment *appsv1.Deployment, conditionPrefix string) []operatorv1.OperatorCondition {
	if deployment.DeletionTimestamp != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "Deleted",
				Message: "Waiting for the OAuth server deployment deletion",
			},
			{
				Type:    conditionPrefix + "Available",
				Status:  operatorv1.ConditionFalse,
				Reason:  "Deleted",
				Message: "The OAuth server deployment is being deleted",
			},
		}
	}

	if deployment.Status.AvailableReplicas > 0 && deployment.Status.UpdatedReplicas != deployment.Status.Replicas {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotReady",
				Message: fmt.Sprintf("Waiting for all OAuth server replicas to be ready (%d not ready)", deployment.Status.Replicas-deployment.Status.UpdatedReplicas),
			},
			{
				Type:    conditionPrefix + "Available",
				Status:  operatorv1.ConditionTrue,
				Reason:  "AsExpected",
				Message: fmt.Sprintf("%d available replicas found for OAuth Server", deployment.Status.AvailableReplicas),
			},
		}
	}

	if deployment.Generation != deployment.Status.ObservedGeneration {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GenerationNotObserved",
				Message: fmt.Sprintf("Waiting for OAuth server observed generation %d to match expected generation %d", deployment.Status.ObservedGeneration, deployment.Generation),
			},
		}
	}

	if deployment.Status.UpdatedReplicas != deployment.Status.Replicas || deployment.Status.UnavailableReplicas > 0 {
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotAvailable",
				Message: fmt.Sprintf("Waiting for %d replicas of OAuth server to be available", deployment.Status.UnavailableReplicas),
			},
		}
	}

	return nil
}
