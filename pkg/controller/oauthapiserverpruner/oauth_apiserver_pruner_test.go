package oauthapiserverpruner

import (
	"context"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakekube "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationv1lister "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestOAuthAPIServerPrunerController(t *testing.T) {
	scenarios := []struct {
		name                      string
		setManagingOAuthAPIServer bool
		apiServicesToMange        []*apiregistrationv1.APIService
		existingNs                *v1.Namespace
		existingSecrets           []*v1.Secret
		expectError               bool
		expectedActions           []string
	}{
		{
			name:                      "no-op because ManagingOAuthAPIServer not set",
			setManagingOAuthAPIServer: true,
		},

		{
			name: "no-op because the api services are managed by CAO",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1", "openshift-oauth-apiserver"),
				newAPIService("oauth.openshift.io", "v1", "openshift-oauth-apiserver"),
			},
		},

		{
			name: "no-op the namespace already removed",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1", "openshift-apiserver"),
				newAPIService("oauth.openshift.io", "v1", "openshift-apiserver"),
			},
		},

		{
			name: "the namespace is removed",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1", "openshift-apiserver"),
				newAPIService("oauth.openshift.io", "v1", "openshift-apiserver"),
			},
			existingNs:      newNamespace("openshift-oauth-apiserver"),
			expectedActions: []string{"delete:namespaces:", "list:secrets:openshift-oauth-apiserver"},
		},

		{
			name: "the namespace is removed and the annotation from the secrets",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1", "openshift-apiserver"),
				newAPIService("oauth.openshift.io", "v1", "openshift-apiserver"),
			},
			existingNs: newNamespace("openshift-oauth-apiserver"),
			existingSecrets: []*v1.Secret{
				newSecret("openshift-oauth-apiserver"),
			},
			expectedActions: []string{"delete:namespaces:", "list:secrets:openshift-oauth-apiserver", "update:secrets:openshift-oauth-apiserver"},
		},

		{
			name: "the namespace is removed",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1", "openshift-apiserver"),
				newAPIService("oauth.openshift.io", "v1", "openshift-apiserver"),
			},
			existingNs: newNamespace("openshift-oauth-apiserver"),
			existingSecrets: []*v1.Secret{
				func() *v1.Secret {
					s := newSecret("openshift-oauth-apiserver")
					s.Finalizers = []string{}
					return s
				}(),
			},
			expectedActions: []string{"delete:namespaces:", "list:secrets:openshift-oauth-apiserver"},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// set up
			initialObjects := []runtime.Object{}
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

				err := fakeAuthOperatorIndexer.Add(authOperator)
				if err != nil {
					t.Fatal(err)
				}
			}
			fakeAPIregistrationIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			{
				for _, apiService := range scenario.apiServicesToMange {
					err := fakeAPIregistrationIndexer.Add(apiService)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			fakeNamespaceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			{
				if scenario.existingNs != nil {
					err := fakeNamespaceIndexer.Add(scenario.existingNs)
					if err != nil {
						t.Fatal(err)
					}
					initialObjects = append(initialObjects, scenario.existingNs)
				}
			}
			for _, existingSecret := range scenario.existingSecrets {
				initialObjects = append(initialObjects, existingSecret)
			}
			fakeKubeClient := fakekube.NewSimpleClientset(initialObjects...)

			// act
			target := &oauthAPIServerPrunerController{
				authOperatorLister:      operatorlistersv1.NewAuthenticationLister(fakeAuthOperatorIndexer),
				apiregistrationv1Lister: apiregistrationv1lister.NewAPIServiceLister(fakeAPIregistrationIndexer),
				namespaceLister:         corev1listers.NewNamespaceLister(fakeNamespaceIndexer),
				secretClient:            fakeKubeClient.CoreV1().Secrets("openshift-oauth-apiserver"),
				namespaceClient:         fakeKubeClient.CoreV1().Namespaces(),
				apiServicesManagedByOAS: []string{"v1.oauth.openshift.io", "v1.user.openshift.io"},
			}
			err := target.sync(context.TODO(), syncContext)

			// validate
			if err != nil && !scenario.expectError {
				t.Fatalf("unexpected error returned %v", err)
			}
			if err == nil && scenario.expectError {
				t.Fatal("expected an error")
			}

			if err = validateActionsVerbs(fakeKubeClient.Actions(), scenario.expectedActions); err != nil {
				t.Fatal(err)
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
	return a.GetVerb() + ":" + a.GetResource().Resource + ":" + a.GetNamespace()
}

func actionStrings(actions []clientgotesting.Action) []string {
	res := make([]string, 0, len(actions))
	for _, a := range actions {
		res = append(res, actionString(a))
	}
	return res
}

func newAPIService(group, version, svcNs string) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: version + "." + group, Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"}},
		Spec:       apiregistrationv1.APIServiceSpec{Group: group, Version: version, Service: &apiregistrationv1.ServiceReference{Namespace: svcNs, Name: "api"}, GroupPriorityMinimum: 9900, VersionPriority: 15},
		Status:     apiregistrationv1.APIServiceStatus{Conditions: []apiregistrationv1.APIServiceCondition{{Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionTrue}}},
	}
}

func newNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func newSecret(ns string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       fmt.Sprintf("encryption-key-%s", ns),
			Namespace:  ns,
			Finalizers: []string{"encryption.apiserver.operator.openshift.io/deletion-protection"},
		},
	}
}
