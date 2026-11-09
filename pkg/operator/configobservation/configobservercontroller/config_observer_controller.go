package configobservation

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
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

	// tempGroupsFieldName is a temporary field used during TLS groups observation.
	// It stores group names temporarily for change detection, then is removed from the final config.
	tempGroupsFieldName = "tempServingInfoGroupsIgnore"
)

func NewConfigObserverController(
	operatorClient v1helpers.OperatorClient,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
	featureGateAccessor featuregates.FeatureGateAccess,
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
		func(listers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (observedConfig map[string]interface{}, errs []error) {
			featureGate, err := featureGateAccessor.CurrentFeatureGates()
			if err != nil {
				return existingConfig, []error{fmt.Errorf("failed to get current feature gates: %w", err)}
			}
			if !featureGate.Enabled(features.FeatureGateTLSGroupPreferences) {
				return apiserver.ObserveTLSSecurityProfileToArguments(
					listers,
					recorder,
					existingConfig,
				)
			}

			// Reconstruct temp groups from existing tls-curve-preferences to prevent spurious events
			if _, err := crypto.CurvePreferencesToGroups[string](existingConfig, []string{"apiServerArguments", "tls-curve-preferences"}, []string{tempGroupsFieldName}); err != nil {
				return existingConfig, []error{err}
			}

			defer func() {
				unstructured.RemoveNestedField(existingConfig, tempGroupsFieldName)
				unstructured.RemoveNestedField(observedConfig, tempGroupsFieldName)
			}()

			observedConfig, errs = apiserver.ObserveTLSSecurityProfileWithGroupPaths(
				listers,
				recorder,
				existingConfig,
				[]string{"apiServerArguments", "tls-min-version"},
				[]string{"apiServerArguments", "tls-cipher-suites"},
				[]string{tempGroupsFieldName},
			)
			if len(errs) > 0 {
				return observedConfig, errs
			}

			if unrecognizedGroups, err := crypto.GroupsToCurvePreferences[string](observedConfig, []string{tempGroupsFieldName}, []string{"apiServerArguments", "tls-curve-preferences"}); err != nil {
				return observedConfig, []error{err}
			} else if len(unrecognizedGroups) > 0 {
				return observedConfig, []error{fmt.Errorf("unrecognized TLS groups: %v", unrecognizedGroups)}
			}

			return observedConfig, errs
		},
		observeauthentication.ObserveAPIAudiences,
		observeoauth.ObserveAccessTokenInactivityTimeout,
		libgoetcd.ObserveStorageURLsToArguments,
		encryptobserver.NewEncryptionConfigObserver("openshift-oauth-apiserver", "/var/run/secrets/encryption-config/encryption-config"),
		featuregates.NewObserveFeatureFlagsFunc(
			sets.New(
				configv1.FeatureGateName("CBORServingAndStorage"),
				configv1.FeatureGateName("ClientsAllowCBOR"),
				configv1.FeatureGateName("ClientsPreferCBOR"),
			),
			nil,
			[]string{"apiServerArguments", "feature-gates"},
			featureGateAccessor,
		),
	} {
		observers = append(observers,
			configobserver.WithPrefix(o, OAuthAPIServerConfigPrefix))
	}

	return configobserver.NewNestedConfigObserver(
		"oauth-apiserver",
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
