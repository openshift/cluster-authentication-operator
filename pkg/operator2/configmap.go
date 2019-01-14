package operator2

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	routev1 "github.com/openshift/api/route/v1"
)

const stubMetadata = `
{
  "issuer": "%s",
  "authorization_endpoint": "%s/oauth/authorize",
  "token_endpoint": "%s/oauth/token",
  "scopes_supported": [
    "user:check-access",
    "user:full",
    "user:info",
    "user:list-projects",
    "user:list-scoped-projects"
  ],
  "response_types_supported": [
    "code",
    "token"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit"
  ],
  "code_challenge_methods_supported": [
    "plain",
    "S256"
  ]
}
`

func getMetadata(route *routev1.Route) string {
	host := route.Spec.Host
	return strings.TrimSpace(fmt.Sprintf(stubMetadata, host, host, host))
}

func getMetadataConfigMap(name string, namespace string, route *routev1.Route) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    defaultLabels(),
		},
		Data: map[string]string{
			metadataKey: getMetadata(route),
		},
	}
}
