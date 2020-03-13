package apiservices_test

import (
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/apiservices"
	"github.com/openshift/library-go/pkg/operator/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

func TestGetAPIServicesToManage(t *testing.T) {
	scenarios := []struct {
		name                       string
		setManagingOAuthAPIServer  bool
		apiServicesToMange         []*apiregistrationv1.APIService
		expectedAPIServicesToMange []*apiregistrationv1.APIService
	}{
		{
			name: "ManagingOAuthAPIServer is NOT set, thus an empty list must be returned",
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1"),
				newAPIService("oauth.openshift.io", "v1"),
			},
			expectedAPIServicesToMange: []*apiregistrationv1.APIService{},
		},
		{
			name:                      "ManagingOAuthAPIServer IS set, thus apiServisesToManage must be returned",
			setManagingOAuthAPIServer: true,
			apiServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1"),
				newAPIService("oauth.openshift.io", "v1"),
			},
			expectedAPIServicesToMange: []*apiregistrationv1.APIService{
				newAPIService("user.openshift.io", "v1"),
				newAPIService("oauth.openshift.io", "v1"),
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// set up
			eventRecorder := events.NewInMemoryRecorder("")
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

			// act
			target := apiservices.NewAPIServicesToManage(operatorlistersv1.NewAuthenticationLister(fakeAuthOperatorIndexer), scenario.apiServicesToMange, eventRecorder)
			actualAPIServicesToMange, err := target.GetAPIServicesToManage()
			if err != nil {
				t.Fatal(err)
			}

			// validate
			if !equality.Semantic.DeepEqual(actualAPIServicesToMange, scenario.expectedAPIServicesToMange) {
				t.Errorf("incorect api services list returned: %s", diff.ObjectDiff(actualAPIServicesToMange, scenario.expectedAPIServicesToMange))
			}
		})
	}
}

func newAPIService(group, version string) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: version + "." + group, Annotations: map[string]string{"service.alpha.openshift.io/inject-cabundle": "true"}},
		Spec:       apiregistrationv1.APIServiceSpec{Group: group, Version: version, Service: &apiregistrationv1.ServiceReference{Namespace: "target-namespace", Name: "api"}, GroupPriorityMinimum: 9900, VersionPriority: 15},
		Status:     apiregistrationv1.APIServiceStatus{Conditions: []apiregistrationv1.APIServiceCondition{{Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionTrue}}},
	}
}
