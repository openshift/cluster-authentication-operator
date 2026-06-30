package preflight

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	kmsservice "k8s.io/kms/pkg/service"
)

func setPodCheckCondition(ctx context.Context, podClient corev1client.PodInterface, podName string, configHash string,
	status *kmsservice.StatusResponse, checkErr error) error {
	return updatePodCheckConditions(ctx, podClient, podName, podCheckConditions(configHash, status, checkErr))
}

func updatePodCheckConditions(ctx context.Context, podClient corev1client.PodInterface, name string, conditions []corev1.PodCondition) error {
	err := retry.OnError(retry.DefaultRetry, isRetriablePodStatusError, func() error {
		pod, err := podClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, condition := range conditions {
			upsertPodCondition(&pod.Status.Conditions, condition)
		}
		_, err = podClient.UpdateStatus(ctx, pod, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to update pod status for %s: %w", name, err)
	}
	return nil
}

func isRetriablePodStatusError(err error) bool {
	return apierrors.IsConflict(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err)
}

func podCheckConditions(configHash string, status *kmsservice.StatusResponse, checkErr error) []corev1.PodCondition {
	now := metav1.Now()

	checkStatus, checkReason, checkMessage := corev1.ConditionTrue, "Succeeded", ""
	if checkErr != nil {
		checkStatus, checkReason, checkMessage = corev1.ConditionFalse, "Failed", checkErr.Error()
	}

	conditions := []corev1.PodCondition{
		{
			Type:               controllers.PodConditionKMSPreflightResult,
			Status:             checkStatus,
			Reason:             checkReason,
			Message:            checkMessage,
			LastTransitionTime: now,
		},
		{
			Type:               controllers.PodConditionKMSPreflightConfigHash,
			Status:             corev1.ConditionTrue,
			Message:            configHash,
			LastTransitionTime: now,
		},
	}

	if status != nil {
		conditions = append(conditions, corev1.PodCondition{
			Type:               controllers.PodConditionKMSPreflightKeyID,
			Status:             corev1.ConditionTrue,
			Message:            status.KeyID,
			LastTransitionTime: now,
		})
	}

	return conditions
}

func upsertPodCondition(conditions *[]corev1.PodCondition, condition corev1.PodCondition) {
	for i := range *conditions {
		if (*conditions)[i].Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}
