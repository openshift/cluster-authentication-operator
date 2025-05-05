package library

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"
)

func WaitForOperatorToPickUpChanges(t *testing.T, configClient configv1client.ConfigV1Interface, name string) error {
	if err := WaitForClusterOperatorProgressing(t, configClient, name); err != nil {
		return fmt.Errorf("authentication operator never became progressing: %v", err)
	}

	if err := WaitForClusterOperatorAvailableNotProgressingNotDegraded(t, configClient, name); err != nil {
		return fmt.Errorf("failed to wait for the authentication operator to become available: %v", err)
	}

	return nil
}

func WaitForClusterOperatorAvailableNotProgressingNotDegraded(t *testing.T, client configv1client.ConfigV1Interface, name string) error {
	return WaitForClusterOperatorStatus(t, client, name,
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
	)
}

func WaitForClusterOperatorDegraded(t *testing.T, client configv1client.ConfigV1Interface, name string) error {
	return WaitForClusterOperatorStatus(t, client, name,
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue},
	)
}

func WaitForClusterOperatorProgressing(t *testing.T, client configv1client.ConfigV1Interface, name string) error {
	return WaitForClusterOperatorStatus(t, client, name,
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue},
	)
}

func WaitForClusterOperatorStatus(t *testing.T, client configv1client.ConfigV1Interface, name string, requiredConditions ...configv1.ClusterOperatorStatusCondition) error {
	return wait.PollUntilContextTimeout(context.TODO(), time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		return checkClusterOperatorStatus(t, ctx, client, name, requiredConditions...)
	})
}

func conditionsStatusString(conditions []configv1.ClusterOperatorStatusCondition) string {
	var result strings.Builder
	orderedConditionTypes := []configv1.ClusterStatusConditionType{configv1.OperatorAvailable, configv1.OperatorProgressing, configv1.OperatorDegraded, configv1.OperatorUpgradeable}
	for i, conditionType := range orderedConditionTypes {
		condition := v1helpers.FindStatusCondition(conditions, conditionType)
		if condition == nil {
			continue
		}
		if i > 0 {
			result.WriteString(", ")
		}
		result.WriteString(fmt.Sprintf("%v: %v", condition.Type, condition.Status))
	}
	return result.String()
}

func WaitForRouteAdmitted(t *testing.T, client routev1client.RouteV1Interface, name, ns string) (string, error) {
	var admittedURL string

	t.Logf("waiting for route %s/%s to be admitted", ns, name)
	err := wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		route, err := client.Routes(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			t.Logf("route.Get(%s/%s) error: %v", ns, name, err)
			return false, nil
		}
		if _, ingress, err := routeapihelpers.IngressURI(route, ""); err != nil {
			t.Log(err)
			return false, nil
		} else {
			admittedURL = ingress.Host
		}
		return true, nil
	})

	return admittedURL, err
}

func WaitForHTTPStatus(t *testing.T, waitDuration time.Duration, client *http.Client, targetURL string, expectedStatus int) error {
	t.Logf("waiting for HEAD at %q to report %d", targetURL, expectedStatus)

	var lastObservedStatus int
	return wait.PollImmediate(time.Second, waitDuration, func() (bool, error) {
		resp, err := client.Head(targetURL)
		if err != nil {
			t.Logf("failed to HEAD %q: %v", targetURL, err)
			return false, nil
		}
		if resp.StatusCode == expectedStatus {
			return true, nil
		}

		if resp.StatusCode != lastObservedStatus { // only log failure once in 10 seconds
			lastObservedStatus = resp.StatusCode
			t.Logf("HEAD %s: %s", targetURL, resp.Status)
		}
		return false, nil
	})
}

func WaitForNewKASRollout(t *testing.T, ctx context.Context, kasClient operatorv1client.KubeAPIServerInterface, origRevision int32) error {
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 30*time.Minute, true, func(ctx context.Context) (bool, error) {
		kas, err := kasClient.Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("kubeapiserver/cluster error: %v", err)
			return false, nil
		}

		for _, nodeStatus := range kas.Status.NodeStatuses {
			if kas.Status.LatestAvailableRevision == origRevision {
				t.Logf("no KAS rollout has started (latest available revision = %d)", kas.Status.LatestAvailableRevision)
				return false, nil
			}

			if nodeStatus.CurrentRevision != kas.Status.LatestAvailableRevision {
				t.Logf("waiting for KAS rollout on node '%s': current revision = %d (latest available = %d)\n", nodeStatus.NodeName, nodeStatus.CurrentRevision, kas.Status.LatestAvailableRevision)
				return false, nil
			}
		}

		return true, nil
	})
	if err != nil {
		return err
	}

	return nil
}

func WaitForClusterOperatorStatusAlwaysAvailable(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string) error {
	return WaitForClusterOperatorStatusStable(t, ctx, client, name,
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
	)
}

// WaitForClusterOperatorStatusStable checks that the specified cluster operator's status does not diverge
// from the conditions specified for 10 minutes. It returns nil if all conditions were matching expectations for that
// period, and an error otherwise.
func WaitForClusterOperatorStatusStable(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string, requiredConditions ...configv1.ClusterOperatorStatusCondition) error {
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		done, err := checkClusterOperatorStatus(t, ctx, client, name, requiredConditions...)
		return !done, err
	})

	if err == context.DeadlineExceeded {
		return nil
	}

	return err
}

func checkClusterOperatorStatus(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string, requiredConditions ...configv1.ClusterOperatorStatusCondition) (bool, error) {
	clusterOperator, err := client.ClusterOperators().Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		t.Logf("clusteroperators.config.openshift.io/%v: %v", name, err)
		return false, nil
	}
	if retry.IsHTTPClientError(err) {
		t.Logf("clusteroperators.config.openshift.io/%v: %v", name, err)
		return false, nil
	}
	conditions := clusterOperator.Status.Conditions
	t.Logf("clusteroperators.config.openshift.io/%v: %v", name, conditionsStatusString(conditions))
	degradedCondition := v1helpers.FindStatusCondition(conditions, configv1.OperatorDegraded)
	if degradedCondition != nil && degradedCondition.Status == configv1.ConditionTrue {
		t.Logf("clusteroperators.config.openshift.io/%v: degraded is true!: %s:%s", name, degradedCondition.Reason, degradedCondition.Message)
	}

	for _, required := range requiredConditions {
		if len(required.Status) > 0 && !v1helpers.IsStatusConditionPresentAndEqual(conditions, required.Type, required.Status) {
			return false, nil
		}
	}

	return true, nil
}
