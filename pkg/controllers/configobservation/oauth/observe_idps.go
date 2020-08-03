package oauth

import (
	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/datasync"
)

var identityProvidersMounts = []string{"volumesToMount", "identityProviders"}

func ObserveIdentityProviders(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	identityProvidersPath := []string{"oauthConfig", "identityProviders"}
	defer func() {
		ret = configobserver.Pruned(ret, identityProvidersPath, identityProvidersMounts)
	}()

	listers := genericlisters.(configobservation.Listers)
	resourceSyncer := genericlisters.ResourceSyncer()
	errs = []error{}

	existingIdentityProviders, _, err := unstructured.NestedFieldCopy(existingConfig, identityProvidersPath...)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	var existingIDPsSlice []interface{}
	if existingIdentityProviders != nil {
		existingIDPsSlice = existingIdentityProviders.([]interface{})
	}

	existingSyncData, err := GetIDPConfigSyncData(existingConfig)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	oauthConfig, err := listers.OAuthLister().Get("cluster")
	if errors.IsNotFound(err) {
		// revert to default state, meaning no IdPs
		klog.Warning("oauth.config.openshift.io/cluster: not found")
		return map[string]interface{}{}, errs
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	// convert identity providers from config to oauth-configuration API and
	// extract the CMs and Secrets that need to be synchronized to the target NS
	convertedObservedIdentityProviders, observedSyncData, idpErrs := convertIdentityProviders(listers.ConfigMapLister, listers.SecretsLister, oauthConfig.Spec.IdentityProviders)
	if len(idpErrs) > 0 {
		return existingConfig, append(errs, idpErrs...)
	}

	observedConfig := map[string]interface{}{}
	if len(convertedObservedIdentityProviders) > 0 {
		if err := unstructured.SetNestedField(observedConfig, convertedObservedIdentityProviders, identityProvidersPath...); err != nil {
			return existingConfig, append(errs, err)
		}
	}

	observedSyncDataBytes, err := observedSyncData.Bytes()
	if err != nil {
		return existingConfig, append(errs, err)
	}

	if !equality.Semantic.DeepEqual(existingIDPsSlice, convertedObservedIdentityProviders) {
		recorder.Eventf("ObserveIdentityProviders", "identity providers changed to %q", convertedObservedIdentityProviders)
	}

	if syncDataErrs := observedSyncData.Validate(listers.ConfigMapLister, listers.SecretsLister); len(syncDataErrs) > 0 {
		return existingConfig, append(errs, syncDataErrs...)
	}

	datasync.HandleIdPConfigSync(resourceSyncer, existingSyncData, observedSyncData)

	if err := unstructured.SetNestedField(observedConfig, string(observedSyncDataBytes), identityProvidersMounts...); err != nil {
		return existingConfig, append(errs, err)
	}

	return observedConfig, errs
}

// GetIDPConfigSyncData returns the data that should be synchronized and mounted
// to the oauth-server container from the observed configuration
func GetIDPConfigSyncData(observedConfig map[string]interface{}) (*datasync.ConfigSyncData, error) {
	currentSyncDataUnstructured, _, err := unstructured.NestedFieldCopy(observedConfig, identityProvidersMounts...)
	if err != nil {
		return nil, err
	}
	currentSyncDataBytes := []byte{}
	if currentSyncDataUnstructured != nil {
		currentSyncDataBytes = []byte(currentSyncDataUnstructured.(string))
	}

	return datasync.NewConfigSyncDataFromJSON(currentSyncDataBytes)
}
