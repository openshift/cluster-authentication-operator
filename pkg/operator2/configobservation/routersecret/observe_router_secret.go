package routersecret

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
)

func ObserveRouterSecret(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	namedCertificatesPath := []string{"servingInfo", "namedCertificates"}
	defer func() {
		ret = configobserver.Pruned(ret, namedCertificatesPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	routerSecret, err := listers.SecretsLister.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs")
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedNamedCertificates, err := routerSecretToSNI(routerSecret)
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedSlice(
		observedConfig,
		observedNamedCertificates,
		namedCertificatesPath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	currentNamedCertificates, _, err := unstructured.NestedSlice(existingConfig, namedCertificatesPath...)
	if err != nil {
		// continue on read error from existing config in an attempt to fix it
		errs = append(errs, err)
	}

	if !equality.Semantic.DeepEqual(currentNamedCertificates, observedNamedCertificates) {
		recorder.Eventf("ObserveRouterSecret", "namedCertificates changed to %#v", observedNamedCertificates)
	}

	return observedConfig, errs
}

func routerSecretToSNI(routerSecret *corev1.Secret) ([]interface{}, error) {
	certs := []interface{}{}
	// make sure the output slice of named certs is sorted by domain so that the generated config is deterministic
	for _, domain := range sets.StringKeySet(routerSecret.Data).List() {
		certs = append(certs, map[string]interface{}{
			"names":    []interface{}{"*." + domain}, // ingress domain is always a wildcard
			"certFile": interface{}("/var/config/system/secrets/v4-0-config-system-router-certs/" + domain),
			"keyFile":  interface{}("/var/config/system/secrets/v4-0-config-system-router-certs/" + domain),
		})
	}

	return certs, nil
}
