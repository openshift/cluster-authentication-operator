package library

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
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
	var done bool
	var conditions []configv1.ClusterOperatorStatusCondition
	var checkErr error

	t.Logf("will wait up to 10m for clusteroperators.config.openshift.io/%s status to be: %v", name, conditionsStatusString(requiredConditions))
	ts := time.Now()
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		done, conditions, checkErr = CheckClusterOperatorStatus(t, ctx, client, name, requiredConditions...)
		return done, checkErr
	})

	if err == nil {
		t.Logf("clusteroperators.config.openshift.io/%s required status reached after %s: %v", name, time.Since(ts), conditionsStatusString(conditions))
		return nil
	}

	t.Logf("clusteroperators.config.openshift.io/%s required status not reached after %s: %v", name, time.Since(ts), conditionsStatusString(conditions))
	return err
}

// WaitForClusterOperatorStatusStable checks that the specified cluster operator's status does not diverge
// from the conditions specified for 10 minutes. It returns nil if all conditions were matching expectations for that
// period, and an error otherwise.
func WaitForClusterOperatorStatusStable(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string, requiredConditions ...configv1.ClusterOperatorStatusCondition) error {
	t.Logf("will wait up to 10m for clusteroperators.config.openshift.io/%s status to be stable: %v", name, conditionsStatusString(requiredConditions))

	var endConditions []configv1.ClusterOperatorStatusCondition
	ts := time.Now()
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 10*time.Minute, true, func(_ context.Context) (bool, error) {
		done, conditions, checkErr := CheckClusterOperatorStatus(t, ctx, client, name, requiredConditions...)
		if len(conditions) > 0 {
			endConditions = conditions
		}
		return !done, checkErr
	})

	if errors.Is(err, context.DeadlineExceeded) {
		t.Logf("clusteroperators.config.openshift.io/%s status was stable for %s; end status: %s", name, time.Since(ts), conditionsStatusString(endConditions))
		return nil
	}

	t.Logf("clusteroperators.config.openshift.io/%s status was not stable for %s; end status: %s (err: %v)", name, time.Since(ts), conditionsStatusString(endConditions), err)
	return err
}

func conditionsStatusString(conditions []configv1.ClusterOperatorStatusCondition) string {
	orderedConditionTypes := []configv1.ClusterStatusConditionType{configv1.OperatorAvailable, configv1.OperatorProgressing, configv1.OperatorDegraded, configv1.OperatorUpgradeable}
	conditionStrings := make([]string, 0, len(orderedConditionTypes))
	for _, conditionType := range orderedConditionTypes {
		condition := v1helpers.FindStatusCondition(conditions, conditionType)
		if condition == nil {
			continue
		}
		conditionStrings = append(conditionStrings, fmt.Sprintf("%s=%s", condition.Type, condition.Status))
	}
	return strings.Join(conditionStrings, "/")
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
	t.Logf("will wait for KAS rollout; latest available revision: %d", origRevision)
	var latestRevision int32
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, 30*time.Minute, true, func(ctx context.Context) (bool, error) {
		kas, err := kasClient.Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("kubeapiserver/cluster error: %v", err)
			return false, nil
		}

		for _, nodeStatus := range kas.Status.NodeStatuses {
			if kas.Status.LatestAvailableRevision == origRevision {
				return false, nil
			}

			if nodeStatus.CurrentRevision != kas.Status.LatestAvailableRevision {
				return false, nil
			}

			latestRevision = nodeStatus.CurrentRevision
		}

		return true, nil
	})
	if err != nil {
		return err
	}

	t.Logf("KAS rollout completed; now at revision %d", latestRevision)
	return nil
}

func WaitForClusterOperatorStatusAlwaysAvailable(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string) error {
	return WaitForClusterOperatorStatusStable(t, ctx, client, name,
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
		configv1.ClusterOperatorStatusCondition{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
	)
}

func CheckClusterOperatorStatus(t *testing.T, ctx context.Context, client configv1client.ConfigV1Interface, name string, requiredConditions ...configv1.ClusterOperatorStatusCondition) (bool, []configv1.ClusterOperatorStatusCondition, error) {
	clusterOperator, err := client.ClusterOperators().Get(ctx, name, metav1.GetOptions{})
	if kerrors.IsNotFound(err) || retry.IsHTTPClientError(err) {
		t.Logf("error while getting clusteroperators.config.openshift.io/%v, will retry: %v", name, err)
		return false, nil, nil
	} else if err != nil {
		return false, nil, err
	}

	conditions := clusterOperator.Status.Conditions
	for _, required := range requiredConditions {
		if len(required.Status) > 0 && !v1helpers.IsStatusConditionPresentAndEqual(conditions, required.Type, required.Status) {
			return false, conditions, nil
		}
	}

	return true, conditions, nil
}
