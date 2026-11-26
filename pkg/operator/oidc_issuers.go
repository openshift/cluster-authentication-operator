package operator

import (
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
)

// parseEndpointURLs parses the endpoint URLs for the proxy config checks, skipping the invalid ones.
func parseEndpointURLs(rawURLs []string) []*url.URL {
	urls := make([]*url.URL, 0, len(rawURLs))
	for _, raw := range rawURLs {
		u, err := url.Parse(raw)
		if err != nil {
			klog.Warningf("skipping invalid endpoint URL %q for the proxy check: %v", raw, err)
			continue
		}
		urls = append(urls, u)
	}
	return urls
}

// objectName returns the name of an informer event object, including deletion tombstones.
func objectName(obj interface{}) (string, bool) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	m, err := meta.Accessor(obj)
	if err != nil {
		return "", false
	}
	return m.GetName(), true
}

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
