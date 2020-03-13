package apiservices

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	operatorlistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

// APIServicesToMange preserve state and clients required to return an authoritative list of API services this operate must manage
type APIServicesToManage struct {
	authOperatorLister operatorlistersv1.AuthenticationLister

	apiServicesToManage        []*apiregistrationv1.APIService
	currentAPIServicesToManage []*apiregistrationv1.APIService

	eventRecorder events.Recorder
}

// NewAPIServicesToManage returns an object that knows how to construct an authoritative list of API services this operator must manage
func NewAPIServicesToManage(
	authOperatorLister operatorlistersv1.AuthenticationLister,
	apiServicesToManage []*apiregistrationv1.APIService,
	eventRecorder events.Recorder) *APIServicesToManage {
	return &APIServicesToManage{
		authOperatorLister:         authOperatorLister,
		apiServicesToManage:        apiServicesToManage,
		eventRecorder:              eventRecorder,
		currentAPIServicesToManage: []*apiregistrationv1.APIService{},
	}
}

// GetAPIServicesToManage returns the desired list of API Services that will be managed by this operator
func (a *APIServicesToManage) GetAPIServicesToManage() ([]*apiregistrationv1.APIService, error) {
	newAPIServicesToManage := a.apiServicesToManage

	authOperator, err := a.authOperatorLister.Get("cluster")
	if err != nil {
		klog.V(4).Infof("unable to determine if auth operator should take OAuth APIs over due to %v", err)
		return nil, err
	}

	if !authOperator.Status.ManagingOAuthAPIServer {
		newAPIServicesToManage = []*apiregistrationv1.APIService{}
	}

	if changed, newAPIServicesSet := apiServicesChanged(a.currentAPIServicesToManage, newAPIServicesToManage); changed {
		a.eventRecorder.Eventf("APIServicesToManageChanged", "The new API Services list this operator will manage is %v", newAPIServicesSet.List())
		a.currentAPIServicesToManage = newAPIServicesToManage
	}

	return a.currentAPIServicesToManage, nil
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
