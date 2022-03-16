package routersecret

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/customroute"
)

func ObserveRouterSecret(
	genericlisters configobserver.Listers,
	recorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, _ []error) {
	namedCertificatesPath := []string{"servingInfo", "namedCertificates"}
	defer func() {
		ret = configobserver.Pruned(ret, namedCertificatesPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	observedNamedCertificates, err := getObservedNamedCertificates(listers)
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

func getObservedNamedCertificates(listers configobservation.Listers) ([]interface{}, error) {
	// Check for custom serving certificate secret
	defaultSecretName := "v4-0-config-system-router-certs"
	secret, err := common.GetActiveRouterSecret(
		listers.SecretsLister,
		"openshift-authentication",
		defaultSecretName,
		"v4-0-config-system-custom-router-certs",
	)
	if err != nil {
		return nil, err
	}

	if secret.GetName() == defaultSecretName {
		return routerSecretToSNI(secret), nil
	}

	ingress, err := listers.IngressLister.Get("cluster")
	if err != nil {
		return nil, err
	}

	return []interface{}{namedCertificate(
		common.GetCustomRouteHostname(ingress, customroute.OAuthComponentRouteNamespace, customroute.OAuthComponentRouteName),
		"/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.crt",
		"/var/config/system/secrets/v4-0-config-system-custom-router-certs/tls.key"),
	}, nil
}

func routerSecretToSNI(routerSecret *corev1.Secret) []interface{} {
	certs := []interface{}{}
	// make sure the output slice of named certs is sorted by domain so that the generated config is deterministic
	for _, domain := range sets.StringKeySet(routerSecret.Data).List() {
		certs = append(
			certs,
			namedCertificate(
				"*."+domain, // ingress domain is always a wildcard
				"/var/config/system/secrets/v4-0-config-system-router-certs/"+domain,
				"/var/config/system/secrets/v4-0-config-system-router-certs/"+domain),
		)
	}
	return certs
}

func namedCertificate(hostname string, certFile string, keyFile string) map[string]interface{} {
	return map[string]interface{}{
		"names":    []interface{}{hostname},
		"certFile": interface{}(certFile),
		"keyFile":  interface{}(keyFile),
	}
}
