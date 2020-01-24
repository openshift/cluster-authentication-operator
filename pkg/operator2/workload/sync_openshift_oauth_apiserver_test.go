package workload

import (
	"fmt"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"io/ioutil"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	clientgotesting "k8s.io/client-go/testing"
	"os"
	"testing"
)

var codec = scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)
var customAPIServerArgsYAML = `
  oauthAPIServer:
    apiServerArguments:
      tls-cipher-suites:
      - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
      - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
      tls-min-version:
      - VersionTLS12`

func TestSyncOAuthAPIServerDaemonSet(t *testing.T) {
	scenarios := []struct {
		name            string
		goldenFile      string
		operator        *operatorv1.Authentication
		expectedActions []string
	}{
		// scenario 1
		{
			name:       "happy path: a daemonset with default values is created",
			goldenFile: "./testdata/sync_ds_scenario_1.yaml",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{}},
			},
			expectedActions: []string{"get:configmaps:config", "get:secrets:etcd-client", "get:configmaps:etcd-serving-ca", "get:configmaps:trusted-ca-bundle", "get:daemonsets:openshift-oauth-apiserver:apiserver", "create:daemonsets:openshift-oauth-apiserver:apiserver"},
		},

		// scenario 2
		{
			name:       "a daemonset with custom flags (for oauthapi server) is created",
			goldenFile: "./testdata/sync_ds_scenario_2.yaml",
			operator: &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{
					ObservedConfig: runtime.RawExtension{Raw: []byte(customAPIServerArgsYAML)},
				}},
			},
			expectedActions: []string{"get:configmaps:config", "get:secrets:etcd-client", "get:configmaps:etcd-serving-ca", "get:configmaps:trusted-ca-bundle", "get:daemonsets:openshift-oauth-apiserver:apiserver", "create:daemonsets:openshift-oauth-apiserver:apiserver"},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("")
			fakeKubeClient := fake.NewSimpleClientset()

			target := &OAuthAPIServerWorkload{
				eventRecorder: eventRecorder,
				kubeClient:    fakeKubeClient,
			}

			ds, err := target.syncDaemonSet(scenario.operator, scenario.operator.Status.Generations)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateActionsVerbs(fakeKubeClient.Actions(), scenario.expectedActions); err != nil {
				t.Fatal(err)
			}

			if len(scenario.goldenFile) > 0 {
				data := readBytesFromFile(t, scenario.goldenFile)
				goldenDs := &appsv1.DaemonSet{}
				if err := runtime.DecodeInto(codec, data, goldenDs); err != nil {
					t.Fatal(err)
				}

				if !equality.Semantic.DeepEqual(ds, goldenDs) {
					t.Errorf("created DaemonSet is different from the expected one (file) : %s", diff.ObjectDiff(ds, goldenDs))
				}
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
