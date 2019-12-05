package configobservation

import (
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

var _ configobserver.Listers = Listers{}

const (
	OAuthServerConfigPrefix    = "oauthServer"
	OAuthAPIServerConfigPrefix = "oauthAPIServer"
)

type Listers struct {
	SecretsLister   corelistersv1.SecretLister
	ConfigMapLister corelistersv1.ConfigMapLister

	APIServerLister_     configlistersv1.APIServerLister
	ConsoleLister        configlistersv1.ConsoleLister
	InfrastructureLister configlistersv1.InfrastructureLister
	OAuthLister          configlistersv1.OAuthLister

	ResourceSync       resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced []cache.InformerSynced
}

func (l Listers) APIServerLister() configlistersv1.APIServerLister {
	return l.APIServerLister_
}

func (l Listers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l Listers) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}
