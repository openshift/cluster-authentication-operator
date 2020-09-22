package common

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corelistersv1 "k8s.io/client-go/listers/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	deploymentutil "github.com/openshift/library-go/pkg/apps/deployment"
)

func CheckDeploymentReady(deployment *appsv1.Deployment, podLister corelistersv1.PodLister, conditionPrefix string) []operatorv1.OperatorCondition {
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
		podMessages, err := deploymentutil.PodContainersStatus(deployment, podLister)
		if err != nil {
			podMessages = []string{fmt.Sprintf("error retrieving pod containers details: %v", err)}
		}

		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotReady",
				Message: fmt.Sprintf("Waiting for all OAuth server replicas to be ready (%d not ready, %s)", deployment.Status.Replicas-deployment.Status.UpdatedReplicas, strings.Join(podMessages, ",")),
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
		podMessages, err := deploymentutil.PodContainersStatus(deployment, podLister)
		if err != nil {
			podMessages = []string{fmt.Sprintf("error retrieving pod containers details: %v", err)}
		}
		return []operatorv1.OperatorCondition{
			{
				Type:    conditionPrefix + "Progressing",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ReplicasNotAvailable",
				Message: fmt.Sprintf("Waiting for %d replicas of OAuth server to be available (%s)", deployment.Status.UnavailableReplicas, strings.Join(podMessages, ",")),
			},
		}
	}

	return nil
}
