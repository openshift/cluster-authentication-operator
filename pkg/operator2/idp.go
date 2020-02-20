package operator2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/utils"
)

// field names are used to uniquely identify a secret or config map reference
// within a given identity provider.  thus the same IDP cannot use the same field
// more than once.  ex: if an idp had two CA fields, it would need to use something
// like ca-1 and ca-2 as the field names to distinguish the two.  the simplest way
// to create a field name is to take the JSON tag and convert it into a format that
// is a valid name for a config map or secret.  ex: clientSecret is not valid as-is
// because of the capital S thus it is converted to client-secret.  the final secret
// name looks like v4-0-config-user-idp-0-client-secret and the final path looks
// like /var/config/user/idp/0/secret/v4-0-config-user-idp-0-client-secret/clientSecret
// note how the end-user has no control over the structure of either value.
var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(osinv1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

type idpData struct {
	provider  runtime.Object
	challenge bool
	login     bool
}

func (c *authOperator) convertProviderConfigToIDPData(providerConfig *configv1.IdentityProviderConfig, syncData *configSyncData, i int) (*idpData, error) {
	const missingProviderFmt string = "type %s was specified, but its configuration is missing"

	data := &idpData{login: true}

	switch providerConfig.Type {
	case configv1.IdentityProviderTypeBasicAuth:
		basicAuthConfig := providerConfig.BasicAuth
		if basicAuthConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.BasicAuthPasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: basicAuthConfig.URL,
				CA:  syncData.addIDPConfigMap(i, basicAuthConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: syncData.addIDPSecret(i, basicAuthConfig.TLSClientCert, "tls-client-cert", corev1.TLSCertKey),
					KeyFile:  syncData.addIDPSecret(i, basicAuthConfig.TLSClientKey, "tls-client-key", corev1.TLSPrivateKeyKey),
				},
			},
		}
		data.challenge = true

	case configv1.IdentityProviderTypeGitHub:
		githubConfig := providerConfig.GitHub
		if githubConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.GitHubIdentityProvider{
			ClientID:      githubConfig.ClientID,
			ClientSecret:  createFileStringSource(syncData.addIDPSecret(i, githubConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			Organizations: githubConfig.Organizations,
			Teams:         githubConfig.Teams,
			Hostname:      githubConfig.Hostname,
			CA:            syncData.addIDPConfigMap(i, githubConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
		}
		data.challenge = false

	case configv1.IdentityProviderTypeGitLab:
		gitlabConfig := providerConfig.GitLab
		if gitlabConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.GitLabIdentityProvider{
			CA:           syncData.addIDPConfigMap(i, gitlabConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
			URL:          gitlabConfig.URL,
			ClientID:     gitlabConfig.ClientID,
			ClientSecret: createFileStringSource(syncData.addIDPSecret(i, gitlabConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			Legacy:       new(bool), // we require OIDC for GitLab now
		}
		data.challenge = true

	case configv1.IdentityProviderTypeGoogle:
		googleConfig := providerConfig.Google
		if googleConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.GoogleIdentityProvider{
			ClientID:     googleConfig.ClientID,
			ClientSecret: createFileStringSource(syncData.addIDPSecret(i, googleConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			HostedDomain: googleConfig.HostedDomain,
		}
		data.challenge = false

	case configv1.IdentityProviderTypeHTPasswd:
		if providerConfig.HTPasswd == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.HTPasswdPasswordIdentityProvider{
			File: syncData.addIDPSecret(i, providerConfig.HTPasswd.FileData, "file-data", configv1.HTPasswdDataKey),
		}
		data.challenge = true

	case configv1.IdentityProviderTypeKeystone:
		keystoneConfig := providerConfig.Keystone
		if keystoneConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.KeystonePasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: keystoneConfig.URL,
				CA:  syncData.addIDPConfigMap(i, keystoneConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: syncData.addIDPSecret(i, keystoneConfig.TLSClientCert, "tls-client-cert", corev1.TLSCertKey),
					KeyFile:  syncData.addIDPSecret(i, keystoneConfig.TLSClientKey, "tls-client-key", corev1.TLSPrivateKeyKey),
				},
			},
			DomainName:          keystoneConfig.DomainName,
			UseKeystoneIdentity: true, // force use of keystone ID
		}
		data.challenge = true

	case configv1.IdentityProviderTypeLDAP:
		ldapConfig := providerConfig.LDAP
		if ldapConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.LDAPPasswordIdentityProvider{
			URL:          ldapConfig.URL,
			BindDN:       ldapConfig.BindDN,
			BindPassword: createFileStringSource(syncData.addIDPSecret(i, ldapConfig.BindPassword, "bind-password", configv1.BindPasswordKey)),
			Insecure:     ldapConfig.Insecure,
			CA:           syncData.addIDPConfigMap(i, ldapConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
			Attributes: osinv1.LDAPAttributeMapping{
				ID:                ldapConfig.Attributes.ID,
				PreferredUsername: ldapConfig.Attributes.PreferredUsername,
				Name:              ldapConfig.Attributes.Name,
				Email:             ldapConfig.Attributes.Email,
			},
		}
		data.challenge = true

	case configv1.IdentityProviderTypeOpenID:
		openIDConfig := providerConfig.OpenID
		if openIDConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		urls, err := c.discoverOpenIDURLs(openIDConfig.Issuer, corev1.ServiceAccountRootCAKey, openIDConfig.CA)
		if err != nil {
			return nil, err
		}

		data.provider = &osinv1.OpenIDIdentityProvider{
			CA:                       syncData.addIDPConfigMap(i, openIDConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
			ClientID:                 openIDConfig.ClientID,
			ClientSecret:             createFileStringSource(syncData.addIDPSecret(i, openIDConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			ExtraScopes:              openIDConfig.ExtraScopes,
			ExtraAuthorizeParameters: openIDConfig.ExtraAuthorizeParameters,
			URLs:                     *urls,
			Claims: osinv1.OpenIDClaims{
				// There is no longer a user-facing setting for ID as it is considered unsafe
				ID:                []string{configv1.UserIDClaim},
				PreferredUsername: openIDConfig.Claims.PreferredUsername,
				Name:              openIDConfig.Claims.Name,
				Email:             openIDConfig.Claims.Email,
			},
		}
		data.challenge = false // TODO perform password grant flow with dummy info to probe for this

	case configv1.IdentityProviderTypeRequestHeader:
		requestHeaderConfig := providerConfig.RequestHeader
		if requestHeaderConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.RequestHeaderIdentityProvider{
			LoginURL:                 requestHeaderConfig.LoginURL,
			ChallengeURL:             requestHeaderConfig.ChallengeURL,
			ClientCA:                 syncData.addIDPConfigMap(i, requestHeaderConfig.ClientCA, "ca", corev1.ServiceAccountRootCAKey),
			ClientCommonNames:        requestHeaderConfig.ClientCommonNames,
			Headers:                  requestHeaderConfig.Headers,
			PreferredUsernameHeaders: requestHeaderConfig.PreferredUsernameHeaders,
			NameHeaders:              requestHeaderConfig.NameHeaders,
			EmailHeaders:             requestHeaderConfig.EmailHeaders,
		}
		data.challenge = len(requestHeaderConfig.ChallengeURL) > 0
		data.login = len(requestHeaderConfig.LoginURL) > 0

	default:
		return nil, fmt.Errorf("the identity provider type '%s' is not supported", providerConfig.Type)
	} // switch

	return data, nil
}

func (c *authOperator) discoverOpenIDURLs(issuer, key string, ca configv1.ConfigMapNameReference) (*osinv1.OpenIDURLs, error) {
	issuer = strings.TrimRight(issuer, "/") // TODO make impossible via validation and remove

	wellKnown := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}

	rt, err := c.transportForCARef(ca, key)
	if err != nil {
		return nil, err
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("couldn't get %v: unexpected response status %v", wellKnown, resp.StatusCode)
	}

	metadata := &openIDProviderJSON{}
	if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %v", err)
	}

	for _, arg := range []struct {
		rawurl   string
		optional bool
	}{
		{
			rawurl:   metadata.AuthURL,
			optional: false,
		},
		{
			rawurl:   metadata.TokenURL,
			optional: false,
		},
		{
			rawurl:   metadata.UserInfoURL,
			optional: true,
		},
	} {
		if !isValidURL(arg.rawurl, arg.optional) {
			return nil, fmt.Errorf("invalid metadata from %s: url=%s optional=%v", wellKnown, arg.rawurl, arg.optional)
		}
	}

	return &osinv1.OpenIDURLs{
		Authorize: metadata.AuthURL,
		Token:     metadata.TokenURL,
		UserInfo:  metadata.UserInfoURL,
	}, nil
}

func (c *authOperator) transportForCARef(ca configv1.ConfigMapNameReference, key string) (http.RoundTripper, error) {
	if len(ca.Name) == 0 {
		return utils.TransportFor("", nil, nil, nil)
	}
	cm, err := c.configMaps.ConfigMaps("openshift-config").Get(ca.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	caData := []byte(cm.Data[key])
	if len(caData) == 0 {
		caData = cm.BinaryData[key]
	}
	if len(caData) == 0 {
		return nil, fmt.Errorf("config map %s/%s has no ca data at key %s", "openshift-config", ca.Name, key)
	}
	return utils.TransportFor("", caData, nil, nil)
}

type openIDProviderJSON struct {
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

func isValidURL(rawurl string, optional bool) bool {
	if len(rawurl) == 0 {
		return optional
	}

	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}

	return u.Scheme == "https" && len(u.Host) > 0 && len(u.Fragment) == 0
}

func createFileStringSource(filepath string) configv1.StringSource {
	return configv1.StringSource{
		StringSourceSpec: configv1.StringSourceSpec{
			File: filepath,
		},
	}
}

func encodeOrDie(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}
	return bytes
}
