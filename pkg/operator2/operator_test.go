package operator2

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	routev1 "github.com/openshift/api/route/v1"
	fakeoauth "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/operator/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHandleVersion(t *testing.T) {
	mockRoundTripResponses["https://route.example.com/healthz"] = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBuffer(nil)),
	}
	mockRoundTripResponses["https://route-will-500.example.com/healthz"] = &http.Response{
		Status:     "Internal Server Error",
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBuffer(nil)),
	}

	for _, testCase := range []struct {
		name                  string
		deploymentAvailable   int
		deploymentUnavailable int
		deploymentUpdated     int
		oauthClients          []string
		routeHost             string
		conditions            []operatorv1.OperatorCondition
		versions              map[string]string
		error                 string
	}{
		{
			name:                  "route: invalid domain; OAuth: happy; deployment: 2 current, available replicas",
			deploymentAvailable:   2,
			deploymentUnavailable: 0,
			deploymentUpdated:     2,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "invalid-domain",
			conditions: []operatorv1.OperatorCondition{
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionTrue, Reason: "FailedGet", Message: "failed to GET route: no mock response for https://invalid-domain/healthz"},
			},
			error: "^unable to check route health: failed to GET route: no mock response for https://invalid-domain/healthz$",
		},
		{
			name:                  "route: 500; OAuth: happy; deployment: 2 current, available replicas",
			deploymentAvailable:   2,
			deploymentUnavailable: 0,
			deploymentUpdated:     2,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route-will-500.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "RouteNotReady", Message: "route not yet available, /healthz returns 'Internal Server Error'"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: only 1 client; deployment: 2 current, available replicas",
			deploymentAvailable:   2,
			deploymentUnavailable: 0,
			deploymentUpdated:     2,
			oauthClients:          []string{"openshift-browser-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionFalse},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthClientNotReady", Message: "challenging oauthclient does not exist"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 0 replicas",
			deploymentAvailable:   0,
			deploymentUnavailable: 0,
			deploymentUpdated:     0,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "AsExpected"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionFalse},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
			versions: map[string]string{
				"oauth-openshift": "operand-version",
				"operator":        "operator-version",
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 unavailable replica",
			deploymentAvailable:   0,
			deploymentUnavailable: 1,
			deploymentUpdated:     0,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 2 unavailable replicas",
			deploymentAvailable:   0,
			deploymentUnavailable: 2,
			deploymentUpdated:     0,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 stale, available replica",
			deploymentAvailable:   1,
			deploymentUnavailable: 0,
			deploymentUpdated:     0,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 current, available replica",
			deploymentAvailable:   1,
			deploymentUnavailable: 0,
			deploymentUpdated:     1,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "AsExpected"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionFalse},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
			versions: map[string]string{
				"oauth-openshift": "operand-version",
				"operator":        "operator-version",
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 stale, available replica and 2 unavailable",
			deploymentAvailable:   1,
			deploymentUnavailable: 2,
			deploymentUpdated:     0,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 current, available replica and 2 unavailable",
			deploymentAvailable:   1,
			deploymentUnavailable: 2,
			deploymentUpdated:     1,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 current, available replica and 1 stale, available replica",
			deploymentAvailable:   2,
			deploymentUnavailable: 0,
			deploymentUpdated:     1,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 2 current, available replicas",
			deploymentAvailable:   2,
			deploymentUnavailable: 0,
			deploymentUpdated:     2,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "AsExpected"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionFalse},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
			versions: map[string]string{
				"oauth-openshift": "operand-version",
				"operator":        "operator-version",
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 1 current, available replica, 1 stale, available replica, and 1 unavailable",
			deploymentAvailable:   2,
			deploymentUnavailable: 1,
			deploymentUpdated:     1,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
		{
			name:                  "route: happy; OAuth: happy; deployment: 2 current, available replicas, 1 stale and 1 unavailable",
			deploymentAvailable:   2,
			deploymentUnavailable: 1,
			deploymentUpdated:     2,
			oauthClients:          []string{"openshift-browser-client", "openshift-challenging-client"},
			routeHost:             "route.example.com",
			conditions: []operatorv1.OperatorCondition{
				{Type: operatorv1.OperatorStatusTypeAvailable, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentHasAvailableReplica"},
				{Type: "OAuthClientsDegraded", Status: operatorv1.ConditionFalse},
				{Type: operatorv1.OperatorStatusTypeProgressing, Status: operatorv1.ConditionTrue, Reason: "OAuthServerDeploymentNotReady", Message: "not all deployment replicas are ready"},
				{Type: "RouteHealthDegraded", Status: operatorv1.ConditionFalse},
				{Type: "WellKnownEndpointDegraded", Status: operatorv1.ConditionFalse},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			maxUnavailable := intstr.FromInt(1)
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name: "oauth-openshift",
				},
				Spec: appsv1.DeploymentSpec{
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RollingUpdateDeploymentStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDeployment{
							MaxUnavailable: &maxUnavailable,
						},
					},
				},
				Status: appsv1.DeploymentStatus{
					Replicas:            int32(testCase.deploymentAvailable + testCase.deploymentUnavailable),
					AvailableReplicas:   int32(testCase.deploymentAvailable),
					UnavailableReplicas: int32(testCase.deploymentUnavailable),
					UpdatedReplicas:     int32(testCase.deploymentUpdated),
				},
			}

			oauthClients := make([]runtime.Object, 0, len(testCase.oauthClients))
			for _, name := range testCase.oauthClients {
				oauthClients = append(oauthClients, &oauthv1.OAuthClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
				})
			}

			authOperator := &authOperator{
				oauthClientClient:  fakeoauth.NewSimpleClientset(oauthClients...).OauthV1().OAuthClients(),
				versionGetter:      status.NewVersionGetter(),
				oauthServerVersion: "operand-version",
				operatorVersion:    "operator-version",
			}
			operatorConfig := &operatorv1.Authentication{}
			authConfig := &configv1.Authentication{}
			route := &routev1.Route{
				Spec: routev1.RouteSpec{Host: testCase.routeHost},
			}
			routeSecret := &corev1.Secret{}
			ingress := &configv1.Ingress{}
			err := authOperator.handleVersion(operatorConfig, authConfig, route, routeSecret, deployment, ingress)

			// normalize the results
			sort.Sort(ByType(operatorConfig.Status.Conditions))
			var zeroTime metav1.Time
			for i := range operatorConfig.Status.Conditions {
				operatorConfig.Status.Conditions[i].LastTransitionTime = zeroTime
			}

			assertEqual(t, testCase.conditions, operatorConfig.Status.Conditions, "conditions")

			if testCase.versions == nil {
				testCase.versions = map[string]string{}
			}
			assertEqual(t, testCase.versions, authOperator.versionGetter.GetVersions(), "versions")

			if testCase.error == "" {
				if err != nil {
					t.Error(err)
				}
			} else if !regexp.MustCompile(testCase.error).MatchString(err.Error()) {
				t.Error(err)
			}
		})
	}
}

func assertEqual(t *testing.T, expected, actual interface{}, message string) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("%s: expected %#v, got %#v", message, expected, actual)
	}
}

// ByType implements sort.Interface for []OperatorCondition based on Type.
type ByType []operatorv1.OperatorCondition

func (a ByType) Len() int           { return len(a) }
func (a ByType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByType) Less(i, j int) bool { return a[i].Type < a[j].Type }
