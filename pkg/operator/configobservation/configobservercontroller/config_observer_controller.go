package configobservation

import (
	"fmt"
	"strconv"

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

// buildCurveIDToGroupMap creates a reverse mapping from numeric curve IDs to TLS group names
// using library-go's public API. This allows reconstructing group names from curve preferences.
func buildCurveIDToGroupMap() map[int32]string {
	reverseMap := make(map[int32]string)
	for _, group := range crypto.ValidTLSGroups() {
		if curveID, ok := crypto.TLSGroupToCurveID(group); ok {
			reverseMap[int32(curveID)] = string(group)
		}
	}
	return reverseMap
}

// Package-level variable to avoid rebuilding the map on every sync
var curveIDToGroup = buildCurveIDToGroupMap()

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

			// Reconstruct temporary groups field from tls-curve-preferences if needed.
			// This prevents spurious "groups changed" events when the temp field was previously empty.
			// Avoids touching the actual servingInfo struct which may be used for other purposes in the future.
			if curvePrefsStrs, found, _ := unstructured.NestedStringSlice(existingConfig, "apiServerArguments", "tls-curve-preferences"); found {
				reconstructedGroups := make([]string, 0, len(curvePrefsStrs))
				for _, cpStr := range curvePrefsStrs {
					cpInt, err := strconv.Atoi(cpStr)
					if err != nil {
						return existingConfig, []error{fmt.Errorf("failed to parse tls-curve-preference %q: %w", cpStr, err)}
					}
					if groupName, ok := curveIDToGroup[int32(cpInt)]; ok {
						reconstructedGroups = append(reconstructedGroups, groupName)
					}
				}
				unstructured.SetNestedStringSlice(existingConfig, reconstructedGroups, tempGroupsFieldName)
			}

			defer func() {
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

			groups, _, err := unstructured.NestedStringSlice(observedConfig, tempGroupsFieldName)
			if err != nil {
				return observedConfig, []error{fmt.Errorf("couldn't get %s: %w", tempGroupsFieldName, err)}
			}

			if len(groups) > 0 {
				curvePreferences, unrecognizedGroups := crypto.TLSGroupsToCurvePreferences(groups)
				if len(unrecognizedGroups) > 0 {
					return observedConfig, []error{fmt.Errorf("unrecognized groups when reading curve preferences: %v", unrecognizedGroups)}
				}

				if len(curvePreferences) > 0 {
					curvePrefsStrings := make([]string, len(curvePreferences))
					for i, cp := range curvePreferences {
						curvePrefsStrings[i] = strconv.Itoa(int(cp))
					}
					if err := unstructured.SetNestedStringSlice(observedConfig, curvePrefsStrings, "apiServerArguments", "tls-curve-preferences"); err != nil {
						return observedConfig, []error{fmt.Errorf("failed to set apiServerArguments.tls-curve-preferences: %w", err)}
					}
				}
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
