package scaling

import (
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
)

const (
	replicasChangedAnnotation      = "authentication.operator.openshift.io/replicas-changed"
	deploymentProgressedAnnotation = "authentication.operator.openshift.io/deployment-progressed"
	scalingBeginTimeout            = 1 * time.Minute
)

// ProcessDeployment ensures the operator does not end up progressing on scaling.
// We define that scaling happens any time .spec.replicas is the only field that changes.
// The idea is then as follows:
//
//  1. When the replicas field is updated, store the change timestamp in a deployment annotation.
//  2. When the deployment eventually starts progressing, add another annotation so that we know it happened.
//  3. When the deployment hasn't progressing for too long, or it has finished progressing, remove all annotations.
//
// When the timestamp annotation is present, we should overwrite Progressing to be false.
//
// So, ProcessDeployment amends the expected deployment in place, also returning any conditions to set on the operator.
func ProcessDeployment(existing, expected *appsv1.Deployment, clock clock.Clock, conditionPrefix string) ([]*applyoperatorv1.OperatorConditionApplyConfiguration, error) {
	if !specsEqualIgnoringReplicas(existing, expected) {
		return nil, nil
	}

	if expected.Annotations == nil {
		expected.Annotations = make(map[string]string)
	}

	if !ptr.Equal(existing.Spec.Replicas, expected.Spec.Replicas) {
		expected.Annotations[replicasChangedAnnotation] = clock.Now().UTC().Format(time.RFC3339)
		return cancelProgressing(conditionPrefix), nil
	}

	var replicasChangedAt time.Time
	if v, ok := existing.Annotations[replicasChangedAnnotation]; ok {
		var err error
		replicasChangedAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("unable to parse annotation %q = %q: %w", replicasChangedAnnotation, v, err)
		}
	}
	if replicasChangedAt.IsZero() {
		return nil, nil
	}

	// Cancel scaling if we are done, or the whole process has reached the specified timeout.
	startedProgressing := existing.Annotations[deploymentProgressedAnnotation] == "true"
	if !isDeploymentProgressing(existing.Status) && (startedProgressing || clock.Since(replicasChangedAt) > scalingBeginTimeout) {
		return nil, nil
	}

	expected.Annotations[replicasChangedAnnotation] = existing.Annotations[replicasChangedAnnotation]
	if startedProgressing || isDeploymentProgressing(existing.Status) {
		expected.Annotations[deploymentProgressedAnnotation] = "true"
	}
	return cancelProgressing(conditionPrefix), nil
}

// specsEqualIgnoringReplicas returns true when the deployment specs are the same or diff only in the replicas field.
// The function returns false automatically when one of the deployments is nil.
func specsEqualIgnoringReplicas(existing, expected *appsv1.Deployment) bool {
	if existing == nil || expected == nil {
		return false
	}

	s1 := &existing.Spec
	s2 := &expected.Spec

	if !ptr.Equal(s1.Replicas, s2.Replicas) {
		s2 = s2.DeepCopy()
		s2.Replicas = s1.Replicas
	}
	return equality.Semantic.DeepEqual(s1, s2)
}

// isDeploymentProgressing returns whether the given deployment is progressing.
func isDeploymentProgressing(status appsv1.DeploymentStatus) bool {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return !(cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable")
		}
	}
	return false
}

func cancelProgressing(conditionPrefix string) []*applyoperatorv1.OperatorConditionApplyConfiguration {
	return []*applyoperatorv1.OperatorConditionApplyConfiguration{
		applyoperatorv1.OperatorCondition().
			WithType(fmt.Sprintf("%sDeploymentProgressing", conditionPrefix)).
			WithStatus(operatorv1.ConditionFalse).
			WithReason("AsExpected").
			WithMessage("Scaling replicas only"),
	}
}
