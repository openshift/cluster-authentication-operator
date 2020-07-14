package configobservation

import (
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	encryptobserver "github.com/openshift/library-go/pkg/operator/encryption/observer"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

var _ configobserver.Listers = Listers{}
var _ encryptobserver.SecretsListers = Listers{}
var _ libgoetcd.ConfigMapLister = Listers{}
var _ libgoetcd.EndpointsLister = Listers{}

type Listers struct {
	APIServerLister_ configlistersv1.APIServerLister
	ConfigMapLister_ corelistersv1.ConfigMapLister
	EndpointsLister_ corelistersv1.EndpointsLister
	SecretLister_    corelistersv1.SecretLister

	ResourceSync       resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced []cache.InformerSynced
}

// APIServerLister used by ObserveAdditionalCORSAllowedOriginsToArguments and ObserveTLSSecurityProfileToArguments,
func (l Listers) APIServerLister() configlistersv1.APIServerLister {
	return l.APIServerLister_
}

func (l Listers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l Listers) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}

func (l Listers) ConfigMapLister() corelistersv1.ConfigMapLister {
	return l.ConfigMapLister_
}

func (l Listers) EndpointsLister() corelistersv1.EndpointsLister {
	return l.EndpointsLister_
}

func (l Listers) SecretLister() corelistersv1.SecretLister {
	return l.SecretLister_
}
