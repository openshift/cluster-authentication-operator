package operator

import (
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

// oidcIssuerDiscoveryURLs returns the OIDC discovery document URLs of the external OIDC providers.
// A configured discoveryURL overrides the one derived from the issuer URL.
func oidcIssuerDiscoveryURLs(auth *configv1.Authentication) []string {
	var urls []string
	for _, provider := range auth.Spec.OIDCProviders {
		switch {
		case len(provider.Issuer.DiscoveryURL) > 0:
			urls = append(urls, provider.Issuer.DiscoveryURL)
		case len(provider.Issuer.URL) > 0:
			urls = append(urls, strings.TrimSuffix(provider.Issuer.URL, "/")+"/.well-known/openid-configuration")
		}
	}
	return urls
}

// oidcIssuerCAConfigMapNames returns the deduplicated names of the openshift-config ConfigMaps
// holding the CA bundles of the external OIDC providers.
func oidcIssuerCAConfigMapNames(auth *configv1.Authentication) []string {
	var names []string
	seen := map[string]struct{}{}
	for _, provider := range auth.Spec.OIDCProviders {
		name := provider.Issuer.CertificateAuthority.Name
		if len(name) == 0 {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}
