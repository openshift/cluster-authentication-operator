package apiservices

import (
	"context"
	"fmt"
	"github.com/openshift/client-go/operator/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/controller/factory"
	corev1 "k8s.io/api/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestManageAPIServicesController(t *testing.T) {
	scenarios := []struct {
		name                      string
		fakeDeployer              *fakeDeployer
		expectError               bool
		expectedActions           []string
		setManagingOAuthAPIServer bool
		setAPIServicesCondition   bool
	}{
		{
			name:                    "happy path",
			setAPIServicesCondition: true,
			fakeDeployer:            newFakeDeployer(true, nil),
			expectedActions:         []string{"update:authentications:"},
		},
		{
			name:         "missing APIServicesAvailable status",
			expectError:  true,
			fakeDeployer: newFakeDeployer(true, nil),
		},
		{
			name:                    "deployer hasn't converged",
			expectError:             false,
			setAPIServicesCondition: true,
			fakeDeployer:            newFakeDeployer(false, nil),
		},
		{
			name:                    "deployer error",
			expectError:             true,
			setAPIServicesCondition: true,
			fakeDeployer:            newFakeDeployer(false, fmt.Errorf("nasty error")),
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// set up
			var fakeOperatorClient *fake.Clientset
			eventRecorder := events.NewInMemoryRecorder("")
			syncContext := factory.NewSyncContext("", eventRecorder)
			fakeAuthOperatorIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			{
				authOperator := &operatorv1.Authentication{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec:       operatorv1.AuthenticationSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
					Status:     operatorv1.AuthenticationStatus{OperatorStatus: operatorv1.OperatorStatus{}, ManagingOAuthAPIServer: scenario.setManagingOAuthAPIServer},
				}

				if scenario.setAPIServicesCondition {
					authOperator.Status.Conditions = []operatorv1.OperatorCondition{
						{
							Type:   "APIServicesAvailable",
							Status: operatorv1.ConditionTrue,
						},
					}
				}

				fakeOperatorClient = fake.NewSimpleClientset(authOperator)
				err := fakeAuthOperatorIndexer.Add(authOperator)
				if err != nil {
					t.Fatal(err)
				}
			}

			// act
			target := syncManageAPIServicesController(scenario.fakeDeployer, fakeOperatorClient.OperatorV1(), operatorlistersv1.NewAuthenticationLister(fakeAuthOperatorIndexer))
			err := target(context.TODO(), syncContext)

			// validate
			if err != nil && !scenario.expectError {
				t.Fatalf("unexpected error returned %v", err)
			}
			if err == nil && scenario.expectError {
				t.Fatal("expected an error")
			}

			err = validateActionsVerbs(fakeOperatorClient.Actions(), scenario.expectedActions)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type fakeDeployer struct {
	converged bool
	err       error
}

func newFakeDeployer(converged bool, err error) *fakeDeployer {
	return &fakeDeployer{converged: converged, err: err}
}

func (d *fakeDeployer) DeployedEncryptionConfigSecret() (secret *corev1.Secret, converged bool, err error) {
	return nil, d.converged, d.err
}

func (d *fakeDeployer) AddEventHandler(handler cache.ResourceEventHandler) {}

func (d *fakeDeployer) HasSynced() bool {
	return true
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
	return a.GetVerb() + ":" + a.GetResource().Resource + ":" + a.GetNamespace()
}

func actionStrings(actions []clientgotesting.Action) []string {
	res := make([]string, 0, len(actions))
	for _, a := range actions {
		res = append(res, actionString(a))
	}
	return res
}
