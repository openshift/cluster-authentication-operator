package workload

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	testlib "github.com/openshift/cluster-authentication-operator/test/library"
	"github.com/openshift/library-go/pkg/operator/events"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

var codec = scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)

var customAPIServerArgsJSON = `
{
  "oauthAPIServer": {
    "apiServerArguments": {
      "cors-allowed-origins": [
        "//127\\.0\\.0\\.1(:|$)",
        "//localhost(:|$)"
      ],
      "tls-cipher-suites": [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
      ],
      "tls-min-version": "VersionTLS12"
    }
  }
}
`

var unsupportedConfigOverridesAPIServerArgsJSON = `
{
  "oauthAPIServer": {
    "apiServerArguments": {
      "tls-cipher-suites": [
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
      ],
      "tls-min-version": "VersionTLS13"
    }
  }
}
`

func TestSyncOAuthAPIServerDeployment(t *testing.T) {
	authIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	authIndexer.Add(&configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeIntegratedOAuth,
		},
	})

	scenarios := []struct {
		name            string
		goldenFile      string
		operator        *operatorv1.Authentication
		expectedActions []string
	}{
		// scenario 1
		{
			name:       "happy path: a deployment with default values is created",
			goldenFile: "./testdata/sync_ds_scenario_1.yaml",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			expectedActions: []string{
				"get:secrets:etcd-client",
				"get:configmaps:etcd-serving-ca",
				"get:configmaps:trusted-ca-bundle",
				"get:deployments:openshift-oauth-apiserver:apiserver",
				"create:deployments:openshift-oauth-apiserver:apiserver",
			},
		},

		// scenario 2
		{
			name:       "a deployment with custom flags (for oauthapi server) is created",
			goldenFile: "./testdata/sync_ds_scenario_2.yaml",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig: runtime.RawExtension{Raw: []byte(customAPIServerArgsJSON)},
				}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			expectedActions: []string{
				"get:secrets:etcd-client",
				"get:configmaps:etcd-serving-ca",
				"get:configmaps:trusted-ca-bundle",
				"get:deployments:openshift-oauth-apiserver:apiserver",
				"create:deployments:openshift-oauth-apiserver:apiserver",
			},
		},

		// scenario 3
		{
			name:       "a deployment with custom flags (for oauthapi server) is created with UnsupportedConfigOverrides",
			goldenFile: "./testdata/sync_ds_scenario_3.yaml",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig:             runtime.RawExtension{Raw: []byte(customAPIServerArgsJSON)},
					UnsupportedConfigOverrides: runtime.RawExtension{Raw: []byte(unsupportedConfigOverridesAPIServerArgsJSON)},
				}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			expectedActions: []string{
				"get:secrets:etcd-client",
				"get:configmaps:etcd-serving-ca",
				"get:configmaps:trusted-ca-bundle",
				"get:deployments:openshift-oauth-apiserver:apiserver",
				"create:deployments:openshift-oauth-apiserver:apiserver",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			fakeKubeClient := fake.NewSimpleClientset()

			target := &OAuthAPIServerWorkload{
				countNodes:                func(nodeSelector map[string]string) (*int32, error) { var i int32; i = 1; return &i, nil },
				ensureAtMostOnePodPerNode: func(spec *appsv1.DeploymentSpec, componentName string) error { return nil },
				kubeClient:                fakeKubeClient,
				authConfigChecker: common.NewAuthConfigChecker(
					testlib.NewFakeInformer[configv1listers.AuthenticationLister](configv1listers.NewAuthenticationLister(authIndexer)),
					testlib.NewFakeInformer[operatorv1listers.KubeAPIServerLister](nil),
					testlib.NewFakeInformer[corelistersv1.ConfigMapLister](nil),
				),
			}

			actualDeployment, _, err := target.syncDeployment(context.TODO(), &scenario.operator.Spec.OperatorSpec, &scenario.operator.Status.OperatorStatus, eventRecorder)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateActionsVerbs(fakeKubeClient.Actions(), scenario.expectedActions); err != nil {
				t.Fatal(err)
			}

			if len(scenario.goldenFile) > 0 {
				data := readBytesFromFile(t, scenario.goldenFile)
				goldenDeployment := &appsv1.Deployment{}
				if err := runtime.DecodeInto(codec, data, goldenDeployment); err != nil {
					t.Fatal(err)
				}

				if !equality.Semantic.DeepEqual(actualDeployment, goldenDeployment) {
					t.Errorf("created Deployment is different from the expected one (file) : %s", cmp.Diff(actualDeployment, goldenDeployment))
				}
			}
		})
	}
}

var emptyAPIServerArgsJSON = `
{
  "oauthAPIServer": {
    "apiServerArguments": {
    }
  }
}
`

var withETCDServerListJSON = `
{
  "oauthAPIServer": {
    "apiServerArguments": {
      "etcd-servers": [
        "https://10.0.131.191:2379",
        "https://10.0.159.206:2379"
      ]
    }
  }
}
`

var withDummytJSON = `
{
  "oauthAPIServer": {
    "apiServerArguments": {
      "dummy-key": [
        "https://10.0.131.191:2379",
        "https://10.0.159.206:2379"
      ]
    }
  }
}
`

func TestPreconditionFulfilled(t *testing.T) {
	scenarios := []struct {
		name            string
		operator        *operatorv1.Authentication
		expectError     bool
		preconditionMet bool
	}{
		// scenario 1
		{
			name: "mandatory etcd-servers is specified",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig: runtime.RawExtension{Raw: []byte(withETCDServerListJSON)},
				}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			preconditionMet: true,
		},

		// scenario 2
		{
			name: "empty APIServerArgs",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig: runtime.RawExtension{Raw: []byte(emptyAPIServerArgsJSON)},
				}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			expectError: true,
		},

		// scenario 3
		{
			name: "no mandatory etcd-servers is specified",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig: runtime.RawExtension{Raw: []byte(withDummytJSON)},
				}},
				Status: operatorv1.AuthenticationStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
				},
			},
			expectError: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			target := &OAuthAPIServerWorkload{}

			// act
			actualPreconditions, err := target.preconditionFulfilledInternal(&scenario.operator.Spec.OperatorSpec, &scenario.operator.Status.OperatorStatus)

			// validate
			if err != nil && !scenario.expectError {
				t.Fatalf("unexpected error returned %v", err)
			}
			if err == nil && scenario.expectError {
				t.Fatal("expected an error")
			}
			if scenario.preconditionMet != actualPreconditions {
				t.Fatalf("unexpected precondtions = %v, expected = %v", actualPreconditions, scenario.preconditionMet)
			}
		})
	}
}

func validateActionsVerbs(actualActions []clientgotesting.Action, expectedActions []string) error {
	if len(actualActions) != len(expectedActions) {
		return fmt.Errorf("expected to get %d actions but got %d\nexpected=%v \n got=%v", len(expectedActions), len(actualActions), expectedActions, actionStrings(actualActions))
	}
	for i, a := range actualActions {
		if got, expected := actionString(a), expectedActions[i]; got != expected {
			return fmt.Errorf("at %d got %s, expected %s", i, got, expected)
		}
	}
	return nil
}

func actionString(a clientgotesting.Action) string {
	involvedObjectName := ""
	if updateAction, isUpdateAction := a.(clientgotesting.UpdateAction); isUpdateAction {
		rawObj := updateAction.GetObject()
		if objMeta, err := meta.Accessor(rawObj); err == nil {
			involvedObjectName = objMeta.GetName()
		}
	}
	if getAction, isGetAction := a.(clientgotesting.GetAction); isGetAction {
		involvedObjectName = getAction.GetName()
	}
	action := a.GetVerb() + ":" + a.GetResource().Resource
	if len(a.GetNamespace()) > 0 {
		action = action + ":" + a.GetNamespace()
	}
	if len(involvedObjectName) > 0 {
		action = action + ":" + involvedObjectName
	}
	return action
}

func actionStrings(actions []clientgotesting.Action) []string {
	res := make([]string, 0, len(actions))
	for _, a := range actions {
		res = append(res, actionString(a))
	}
	return res
}

func readBytesFromFile(t *testing.T, filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
