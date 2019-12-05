package configobservercontroller

import (
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation/console"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation/infrastructure"
)

func NewConfigObserver(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
) factory.Controller {
	interestingNamespaces := []string{
		"openshift-authentication",
	}

	preRunCacheSynced := []cache.InformerSynced{}
	for _, ns := range interestingNamespaces {
		preRunCacheSynced = append(preRunCacheSynced,
			kubeInformersForNamespaces.InformersFor(ns).Core().V1().ConfigMaps().Informer().HasSynced,
		)
	}

	informers := []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
		configInformer.Config().V1().Consoles().Informer(),
		configInformer.Config().V1().Infrastructures().Informer(),
	}

	for _, ns := range interestingNamespaces {
		informers = append(informers, kubeInformersForNamespaces.InformersFor(ns).Core().V1().ConfigMaps().Informer())
	}

	return configobserver.NewConfigObserver(
		operatorClient,
		eventRecorder,
		configobservation.Listers{
			APIServerLister_:     configInformer.Config().V1().APIServers().Lister(),
			ConsoleLister:        configInformer.Config().V1().Consoles().Lister(),
			InfrastructureLister: configInformer.Config().V1().Infrastructures().Lister(),
			ResourceSync:         resourceSyncer,
			PreRunCachesSynced: append(preRunCacheSynced,
				operatorClient.Informer().HasSynced,

				configInformer.Config().V1().APIServers().Informer().HasSynced,
				configInformer.Config().V1().Consoles().Informer().HasSynced,
				configInformer.Config().V1().Infrastructures().Informer().HasSynced,
			),
		},
		informers,
		apiserver.ObserveAdditionalCORSAllowedOrigins,
		apiserver.ObserveTLSSecurityProfile,
		console.ObserveConsoleURL,
		infrastructure.ObserveAPIServerURL,
	)
}
