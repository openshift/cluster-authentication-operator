package configobservercontroller

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	configobserveroauth "github.com/openshift/library-go/pkg/operator/configobserver/oauth"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/console"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/infrastructure"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/routersecret"
)

func NewConfigObserver(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	enabledClusterCapabilities sets.String,
	eventRecorder events.Recorder,
) factory.Controller {
	interestingNamespaces := []string{
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
	}

	preRunCacheSynced := []cache.InformerSynced{
		operatorClient.Informer().HasSynced,
		configInformer.Config().V1().APIServers().Informer().HasSynced,
		configInformer.Config().V1().Infrastructures().Informer().HasSynced,
		configInformer.Config().V1().OAuths().Informer().HasSynced,
		configInformer.Config().V1().Ingresses().Informer().HasSynced,
		configInformer.Config().V1().ClusterVersions().Informer().HasSynced,
	}

	informers := []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
		configInformer.Config().V1().Infrastructures().Informer(),
		configInformer.Config().V1().OAuths().Informer(),
		configInformer.Config().V1().Ingresses().Informer(),
		configInformer.Config().V1().ClusterVersions().Informer(),
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
		infrastructure.ObserveAPIServerURL,
		oauth.ObserveIdentityProviders,
		oauth.ObserveTemplates,
		oauth.ObserveTokenConfig,
		oauth.ObserveAudit,
		configobserveroauth.ObserveAccessTokenInactivityTimeout,
		routersecret.ObserveRouterSecret,
	} {
		oauthServerObservers = append(oauthServerObservers,
			configobserver.WithPrefix(o, configobservation.OAuthServerConfigPrefix))
	}

	listers := configobservation.Listers{
		ConfigMapLister: kubeInformersForNamespaces.ConfigMapLister(),
		SecretsLister:   kubeInformersForNamespaces.SecretLister(),
		IngressLister:   configInformer.Config().V1().Ingresses().Lister(),

		APIServerLister_:     configInformer.Config().V1().APIServers().Lister(),
		ClusterVersionLister: configInformer.Config().V1().ClusterVersions().Lister(),
		InfrastructureLister: configInformer.Config().V1().Infrastructures().Lister(),
		OAuthLister_:         configInformer.Config().V1().OAuths().Lister(),
		ResourceSync:         resourceSyncer,
		PreRunCachesSynced:   preRunCacheSynced,
	}

	// Check if the Console capability is enabled on the cluster and sync and add its informer, lister, and config observer
	if enabledClusterCapabilities.Has("Console") {
		listers.PreRunCachesSynced = append(listers.PreRunCachesSynced, configInformer.Config().V1().Consoles().Informer().HasSynced)
		informers = append(informers, configInformer.Config().V1().Consoles().Informer())
		listers.ConsoleLister = configInformer.Config().V1().Consoles().Lister()
		oauthServerObservers = append(oauthServerObservers, configobserver.WithPrefix(console.ObserveConsoleURL, configobservation.OAuthServerConfigPrefix))
	}

	return configobserver.NewNestedConfigObserver(
		operatorClient,
		eventRecorder,
		listers,
		informers,
		[]string{configobservation.OAuthServerConfigPrefix},
		"OAuthServer",
		oauthServerObservers...,
	)
}
