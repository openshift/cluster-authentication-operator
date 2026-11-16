package operator

import (
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

// extractIdPURLs returns external URLs from configured identity providers.
func extractIdPURLs(oauthConfig *configv1.OAuth) []string {
	var urls []string
	for _, idp := range oauthConfig.Spec.IdentityProviders {
		switch {
		case idp.OpenID != nil && len(idp.OpenID.Issuer) > 0:
			issuer := strings.TrimSuffix(idp.OpenID.Issuer, "/")
			urls = append(urls, issuer+"/.well-known/openid-configuration")
		case idp.GitHub != nil:
			host := idp.GitHub.Hostname
			if len(host) == 0 {
				host = "github.com"
			}
			urls = append(urls, "https://"+host)
		case idp.GitLab != nil && len(idp.GitLab.URL) > 0:
			urls = append(urls, idp.GitLab.URL)
		case idp.Keystone != nil && len(idp.Keystone.URL) > 0:
			urls = append(urls, idp.Keystone.URL)
		case idp.BasicAuth != nil && len(idp.BasicAuth.URL) > 0:
			urls = append(urls, idp.BasicAuth.URL)
		case idp.Google != nil:
			urls = append(urls, "https://accounts.google.com")
		}
	}
	return urls
}
