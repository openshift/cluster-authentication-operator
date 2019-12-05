package console

import (
	"fmt"
	"net/url"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
)

func ObserveConsoleURL(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	assetPublicURLPath := []string{"oauthConfig", "assetPublicURL"}
	defer func() {
		ret = configobserver.Pruned(ret, assetPublicURLPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	consoleConfig, err := listers.ConsoleLister.Get("cluster")
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedAssetURL := consoleConfig.Status.ConsoleURL
	if _, err := url.Parse(observedAssetURL); err != nil { // should never happen
		return existingConfig, append(errs, fmt.Errorf("failed to parse consoleURL %q: %w", observedAssetURL, err))
	}

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedField(
		observedConfig,
		observedAssetURL,
		assetPublicURLPath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	currentAssetURL, _, err := unstructured.NestedString(existingConfig, assetPublicURLPath...)
	if err != nil {
		// continue on read error from existing config in an attempt to fix it
		errs = append(errs, err)
	}

	if currentAssetURL != observedAssetURL {
		recorder.Eventf("ObserveConsoleURL", "assetPublicURL changed from %s to %s", currentAssetURL, observedAssetURL)
	}

	return observedConfig, errs
}
