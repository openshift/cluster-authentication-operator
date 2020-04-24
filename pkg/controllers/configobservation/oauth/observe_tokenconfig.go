package oauth

import (
	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

const (
	defaultAccessTokenMaxAgeSeconds    = float64(86400) // a day
	defaultAuthorizeTokenMaxAgeSeconds = float64(300)   // 5 minutes
)

func ObserveTokenConfig(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	tokenConfigPath := []string{"oauthConfig", "tokenConfig"}
	defer func() {
		ret = configobserver.Pruned(ret, tokenConfigPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs = []error{}

	existingConfig, _, err := unstructured.NestedMap(existingConfig, tokenConfigPath...)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	existingAccessTokenMaxAgeSeconds, _, err := unstructured.NestedFloat64(existingConfig, "accessTokenMaxAgeSeconds")
	if err != nil {
		errs = append(errs, err)
	}

	existingAccessTokenInactivityTimeoutSeconds, _, err := unstructured.NestedFieldCopy(existingConfig, "accessTokenInactivityTimeoutSeconds")
	if err != nil {
		errs = append(errs, err)
	}
	var existingAccessTokenInactivityTimeoutSecondsFloat *float64
	if existingAccessTokenInactivityTimeoutSeconds != nil {
		if f, ok := existingAccessTokenInactivityTimeoutSeconds.(float64); ok {
			existingAccessTokenInactivityTimeoutSecondsFloat = &f
		}
	}

	observedTokenConfigFieldMap := map[string]interface{}{
		"accessTokenMaxAgeSeconds":    defaultAccessTokenMaxAgeSeconds,
		"authorizeTokenMaxAgeSeconds": defaultAuthorizeTokenMaxAgeSeconds,
	}
	observedConfig := map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"tokenConfig": observedTokenConfigFieldMap,
		},
	}
	oauthConfig, err := listers.OAuthLister.Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warning("oauth.config.openshift.io/cluster: not found")
		return observedConfig, errs
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	observedAccessTokenMaxAgeSeconds := float64(oauthConfig.Spec.TokenConfig.AccessTokenMaxAgeSeconds)
	if observedAccessTokenMaxAgeSeconds == 0 {
		observedAccessTokenMaxAgeSeconds = defaultAccessTokenMaxAgeSeconds
	}
	observedTokenConfigFieldMap["accessTokenMaxAgeSeconds"] = observedAccessTokenMaxAgeSeconds

	observedAccessTokenInactivityTimeoutSeconds := convertAccessTokenInactivityTimeout(oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeoutSeconds)
	if observedAccessTokenInactivityTimeoutSeconds != nil {
		observedTokenConfigFieldMap["accessTokenInactivityTimeoutSeconds"] = *observedAccessTokenInactivityTimeoutSeconds
	}

	if err := unstructured.SetNestedMap(
		observedConfig,
		observedTokenConfigFieldMap,
		tokenConfigPath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	if !(existingAccessTokenMaxAgeSeconds == observedAccessTokenMaxAgeSeconds) {
		recorder.Eventf("ObserveTokenConfig", "accessTokenMaxAgeSeconds changed from %d to %d", existingAccessTokenMaxAgeSeconds, observedAccessTokenMaxAgeSeconds)
	}

	if !(existingAccessTokenInactivityTimeoutSecondsFloat == observedAccessTokenInactivityTimeoutSeconds) {
		recorder.Eventf("ObserveTokenConfig", "accessTokenInactivityTimeoutSeconds changed from %d to %d", existingAccessTokenInactivityTimeoutSecondsFloat, observedAccessTokenInactivityTimeoutSeconds)

	}

	return observedConfig, errs
}

func convertAccessTokenInactivityTimeout(observedValue int32) *float64 {
	var ret *float64
	floatVal := float64(observedValue)
	switch {
	case floatVal == 0:
		ret = nil
	case floatVal < 0:
		zero := float64(0)
		ret = &zero
	case floatVal > 0:
		ret = &floatVal
	}

	return ret
}
