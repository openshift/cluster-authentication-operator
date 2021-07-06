package configobservation

import (
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	encryptobserver "github.com/openshift/library-go/pkg/operator/encryption/observer"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
	observeauthentication "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/authentication"
	observeoauth "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/oauth"
)

const (
	OAuthAPIServerConfigPrefix = "oauthAPIServer"
)

func NewConfigObserverController(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
) factory.Controller {

	preRunCacheSynced := []cache.InformerSynced{
		operatorClient.Informer().HasSynced,

		// for cors, audiences and tls observers
		configInformer.Config().V1().APIServers().Informer().HasSynced,
		configInformer.Config().V1().Authentications().Informer().HasSynced,
		configInformer.Config().V1().OAuths().Informer().HasSynced,

		// for etcd observer
		kubeInformersForNamespaces.InformersFor(libgoetcd.EtcdEndpointNamespace).Core().V1().Endpoints().Informer().HasSynced,
		kubeInformersForNamespaces.InformersFor(libgoetcd.EtcdEndpointNamespace).Core().V1().ConfigMaps().Informer().HasSynced,

		// for encryption-config observer
		kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Secrets().Informer().HasSynced,
	}

	informers := []factory.Informer{
		operatorClient.Informer(),

		// for cors, audiences and tls observers
		configInformer.Config().V1().APIServers().Informer(),
		configInformer.Config().V1().Authentications().Informer(),
		configInformer.Config().V1().OAuths().Informer(),

		// for etcd observer
		kubeInformersForNamespaces.InformersFor(libgoetcd.EtcdEndpointNamespace).Core().V1().Endpoints().Informer(),
		kubeInformersForNamespaces.InformersFor(libgoetcd.EtcdEndpointNamespace).Core().V1().ConfigMaps().Informer(),

		// for encryption-config observer
		kubeInformersForNamespaces.InformersFor("openshift-oauth-apiserver").Core().V1().Secrets().Informer(),
	}

	observers := []configobserver.ObserveConfigFunc{}
	for _, o := range []configobserver.ObserveConfigFunc{
		apiserver.ObserveAdditionalCORSAllowedOriginsToArguments,
		apiserver.ObserveTLSSecurityProfileToArguments,
		observeauthentication.ObserveAPIAudiences,
		observeoauth.ObserveAccessTokenInactivityTimeout,
		libgoetcd.ObserveStorageURLsToArguments,
		encryptobserver.NewEncryptionConfigObserver("openshift-oauth-apiserver", "/var/run/secrets/encryption-config/encryption-config"),
	} {
		observers = append(observers,
			configobserver.WithPrefix(o, OAuthAPIServerConfigPrefix))
	}

	return configobserver.NewNestedConfigObserver(
		operatorClient,
		eventRecorder,
		configobservation.Listers{
			APIServerLister_:   configInformer.Config().V1().APIServers().Lister(),
			AuthConfigLister_:  configInformer.Config().V1().Authentications().Lister(),
			ConfigMapLister_:   kubeInformersForNamespaces.ConfigMapLister(),
			EndpointsLister_:   kubeInformersForNamespaces.InformersFor(libgoetcd.EtcdEndpointNamespace).Core().V1().Endpoints().Lister(),
			OAuthLister_:       configInformer.Config().V1().OAuths().Lister(),
			SecretLister_:      kubeInformersForNamespaces.SecretLister(),
			ResourceSync:       resourceSyncer,
			PreRunCachesSynced: preRunCacheSynced,
		},
		informers,
		[]string{OAuthAPIServerConfigPrefix},
		"OAuthAPIServer",
		observers...,
	)
}
