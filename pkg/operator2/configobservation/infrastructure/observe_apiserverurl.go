package infrastructure

import (
	"fmt"
	"net/url"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
)

func ObserveAPIServerURL(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	loginURLPath := []string{"oauthConfig", "loginURL"}
	defer func() {
		ret = configobserver.Pruned(ret, loginURLPath)
	}()
	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	infrastructureConfig, err := listers.InfrastructureLister.Get("cluster")
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedLoginURL := infrastructureConfig.Status.APIServerURL
	if _, err := url.Parse(observedLoginURL); err != nil { // should never happen
		return existingConfig, append(errs, fmt.Errorf("failed to parse apiServerURL %q: %w", observedLoginURL, err))
	}

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedField(
		observedConfig,
		observedLoginURL,
		loginURLPath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	currentLoginURL, _, err := unstructured.NestedString(existingConfig, loginURLPath...)
	if err != nil {
		// continue on read error from existing config in an attempt to fix it
		errs = append(errs, err)
	}

	if currentLoginURL != observedLoginURL {
		recorder.Eventf("ObserveAPIServerURL", "loginURL changed from %s to %s", currentLoginURL, observedLoginURL)
	}

	return observedConfig, errs
}
