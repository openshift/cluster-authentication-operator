package common

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
)

func GetIngressConfig(ingressLister configv1lister.IngressLister, conditionPrefix string) (*configv1.Ingress, []operatorv1.OperatorCondition) {
	ingress, err := ingressLister.Get("cluster")
	if err != nil {
		return nil, []operatorv1.OperatorCondition{{
			Type:    conditionPrefix + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "NotFound",
			Message: fmt.Sprintf("Unable to get cluster ingress config: %v", err),
		}}
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, []operatorv1.OperatorCondition{{
			Type:    conditionPrefix + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Invalid",
			Message: fmt.Sprintf("The ingress config domain cannot be empty"),
		}}
	}
	return ingress, nil
}

// GetComponentRouteSpec searches the entries of the ingress.spec.componentRoutes array for a componentRoute with a matching namespace and name.
// If a matching componentRoute is found a pointer to it is returned, otherwise nil is returned.
func GetComponentRouteSpec(ingress *configv1.Ingress, namespace string, name string) *configv1.ComponentRouteSpec {
	componentRoutes := ingress.Spec.ComponentRoutes
	for i := range componentRoutes {
		if componentRoutes[i].Namespace == namespace &&
			componentRoutes[i].Name == name {
			return &componentRoutes[i]
		}
	}
	return nil
}

// GetComponentRouteStatus searches the entries of the ingress.status.componentRoutes array for a componentRoute with a matching namespace and name.
// If a matching componentRoute is found a pointer to it is returned, otherwise nil is returned.
func GetComponentRouteStatus(ingress *configv1.Ingress, namespace string, name string) *configv1.ComponentRouteStatus {
	componentRoutes := ingress.Status.ComponentRoutes
	for i := range componentRoutes {
		if componentRoutes[i].Namespace == namespace &&
			componentRoutes[i].Name == name {
			return &componentRoutes[i]
		}
	}
	return nil
}

// GetCustomRouteHostname searches the entries of the ingress.spec.componentRoutes array for a componentRoute with a matching namespace and name.
// If a matching componentRoute is found, the hostname defined in the entry if found, otherwise an empty string is returned.
func GetCustomRouteHostname(ingress *configv1.Ingress, namespace string, name string) string {
	if componentRoute := GetComponentRouteSpec(ingress, namespace, name); componentRoute != nil {
		return string(componentRoute.Hostname)
	}
	return ""
}

// GetActiveRouterCertKeyBytes returns a byte array containing the server certificates, a byte array containing the private key,
// a boolean representing if the default openshift-authentication/v4-0-config-system-router-certs secret is being used, and
// any errors retrieving the active router secret.
func GetActiveRouterCertKeyBytes(secretLister corev1listers.SecretLister, ingressConfig *configv1.Ingress, namespace string, defaultSecretName string, customSecretName string) ([]byte, []byte, bool, error) {
	secret, err := GetActiveRouterSecret(secretLister, namespace, defaultSecretName, customSecretName)
	if err != nil {
		return nil, nil, false, err
	}

	tlsCertKey := corev1.TLSCertKey
	tlsPrivateKeyKey := corev1.TLSPrivateKeyKey
	isDefault := secret.GetName() == defaultSecretName
	if isDefault {
		tlsCertKey = ingressConfig.Spec.Domain
		tlsPrivateKeyKey = ingressConfig.Spec.Domain
	}

	cert := secret.Data[tlsCertKey]
	privateKey := secret.Data[tlsPrivateKeyKey]

	return cert, privateKey, isDefault, nil
}

// GetActiveRouterSecret returns the secret that contains the serving certificates for the openshift-authentication/oauth-openshift
// route, a boolean representing if the default openshift-authentication/v4-0-config-system-router-certs secret is being used, and
// any errors in retrieving the active secret.
func GetActiveRouterSecret(secretLister corev1listers.SecretLister, namespace string, defaultSecretName string, customSecretName string) (*corev1.Secret, error) {
	secret, err := secretLister.Secrets(namespace).Get(customSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}

		// Custom serving certificate secret does not exist, use default secret instead
		secret, err = secretLister.Secrets(namespace).Get(defaultSecretName)
		if err != nil {
			return nil, err
		}
	}

	return secret, nil
}
