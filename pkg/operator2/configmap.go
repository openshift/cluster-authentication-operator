package operator2

import (
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
)

const stubMetadata = `
{
  "issuer": "https://%s",
  "authorization_endpoint": "https://%s/oauth/authorize",
  "token_endpoint": "https://%s/oauth/token",
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

func getMetadataStruct(route *routev1.Route) map[string]interface{} {
	var ret map[string]interface{}

	metadataJSON := getMetadata(route)
	err := json.Unmarshal([]byte(metadataJSON), &ret)
	if err != nil {
		// should never happen unless the static metadata is broken
		panic(err)
	}

	return ret
}

// TODO: the code in this file does not reflect situations where the
// OAuthMetadata field of the Authentication object is set
func getMetadata(route *routev1.Route) string {
	host := route.Spec.Host
	return strings.TrimSpace(fmt.Sprintf(stubMetadata, host, host, host))
}

func getMetadataConfigMap(route *routev1.Route) *corev1.ConfigMap {
	meta := defaultMeta()
	meta.Name = "v4-0-config-system-metadata"
	return &corev1.ConfigMap{
		ObjectMeta: meta,
		Data: map[string]string{
			configv1.OAuthMetadataKey: getMetadata(route),
		},
	}
}
