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
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation/oauth"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation/routersecret"
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
		"openshift-config",
	}

	preRunCacheSynced := []cache.InformerSynced{
		operatorClient.Informer().HasSynced,
		configInformer.Config().V1().APIServers().Informer().HasSynced,
		configInformer.Config().V1().Consoles().Informer().HasSynced,
		configInformer.Config().V1().Infrastructures().Informer().HasSynced,
		configInformer.Config().V1().OAuths().Informer().HasSynced,
	}

	informers := []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
		configInformer.Config().V1().Consoles().Informer(),
		configInformer.Config().V1().Infrastructures().Informer(),
		configInformer.Config().V1().OAuths().Informer(),
	}

	for _, ns := range interestingNamespaces {
		preRunCacheSynced = append(preRunCacheSynced,
			kubeInformersForNamespaces.InformersFor(ns).Core().V1().ConfigMaps().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(ns).Core().V1().Secrets().Informer().HasSynced,
		)

		informers = append(informers,
			kubeInformersForNamespaces.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
			kubeInformersForNamespaces.InformersFor(ns).Core().V1().Secrets().Informer(),
		)
	}

	oauthServerObservers := []configobserver.ObserveConfigFunc{}
	for _, o := range []configobserver.ObserveConfigFunc{
		apiserver.ObserveAdditionalCORSAllowedOrigins,
		apiserver.ObserveTLSSecurityProfile,
		console.ObserveConsoleURL,
		infrastructure.ObserveAPIServerURL,
		oauth.ObserveIdentityProviders,
		oauth.ObserveTemplates,
		routersecret.ObserveRouterSecret,
	} {
		oauthServerObservers = append(oauthServerObservers,
			configobserver.WithPrefix(o, configobservation.OAuthServerConfigPrefix))
	}

	return configobserver.NewConfigObserver(
		operatorClient,
		eventRecorder,
		configobservation.Listers{
			ConfigMapLister: kubeInformersForNamespaces.ConfigMapLister(),
			SecretsLister:   kubeInformersForNamespaces.SecretLister(),

			APIServerLister_:     configInformer.Config().V1().APIServers().Lister(),
			ConsoleLister:        configInformer.Config().V1().Consoles().Lister(),
			InfrastructureLister: configInformer.Config().V1().Infrastructures().Lister(),
			OAuthLister:          configInformer.Config().V1().OAuths().Lister(),
			ResourceSync:         resourceSyncer,
			PreRunCachesSynced:   preRunCacheSynced,
		},
		informers,
		oauthServerObservers...,
	)
}
