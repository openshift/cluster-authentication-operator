package apiservices

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

// APIServicesToManage returns the current list of APIServices managed by this operator.
// If authOperator.status.managingOAuthAPIServer is false, the empty is returned, otherwise
// the full list of APIServices.
type APIServicesToManage struct {
	authOperatorLister operatorlistersv1.AuthenticationLister
	all                []*apiregistrationv1.APIService
}

// NewAPIServicesToManage returns an object that knows how to construct an authoritative list of API services this operator must manage
func NewAPIServicesToManage(authOperatorLister operatorlistersv1.AuthenticationLister, all []*apiregistrationv1.APIService) *APIServicesToManage {
	return &APIServicesToManage{
		authOperatorLister: authOperatorLister,
		all:                all,
	}
}

// GetAPIServicesToManage returns the desired list of API Services that will be managed by this operator
// Note that at the moment the returned list is dynamic and depends on authOperator.Status.ManagingOAuthAPIServer field
//
// TODO: change this function in 4.7 to return initial/full/authoritative list of APIs to manage
func (a *APIServicesToManage) GetAPIServicesToManage() ([]*apiregistrationv1.APIService, error) {
	authOperator, err := a.authOperatorLister.Get("cluster")
	if err != nil {
		klog.V(4).Infof("unable to determine if auth operator should take OAuth APIs over due to %v", err)
		return nil, err
	}

	if !authOperator.Status.ManagingOAuthAPIServer {
		return []*apiregistrationv1.APIService{}, nil
	}

	return a.all, nil
}

// WithChangeEvent creates an event when the result of GetAPIServicesToManage changes in consecutive calls.
type WithChangeEvent struct {
	APIServicesToManage *APIServicesToManage
	EventRecorder       events.Recorder

	lock         sync.Mutex
	lastReturned []*apiregistrationv1.APIService
}

func (a *WithChangeEvent) GetAPIServicesToManage() ([]*apiregistrationv1.APIService, error) {
	l, err := a.APIServicesToManage.GetAPIServicesToManage()
	if err != nil {
		return nil, err
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	if changed, newAPIServicesSet := apiServicesChanged(a.lastReturned, l); changed {
		a.EventRecorder.Eventf("APIServicesToManageChanged", "The new API Services list this operator will manage is %v", newAPIServicesSet.List())
		a.lastReturned = l
	}

	return l, err
}

func apiServicesChanged(old []*apiregistrationv1.APIService, new []*apiregistrationv1.APIService) (bool, sets.String) {
	oldSet := sets.String{}
	for _, oldService := range old {
		oldSet.Insert(oldService.Name)
	}

	newSet := sets.String{}
	for _, newService := range new {
		newSet.Insert(newService.Name)
	}

	removed := oldSet.Difference(newSet).List()
	added := newSet.Difference(oldSet).List()
	return len(removed) > 0 || len(added) > 0, newSet
}
