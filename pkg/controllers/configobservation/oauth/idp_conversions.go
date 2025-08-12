package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/datasync"
	"github.com/openshift/cluster-authentication-operator/pkg/transport"
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

	// save latest OIDC password grant check not to bomb the provider with
	// login requests each sync loop
	// map is checkedSecretResourceVersion -> passwordGrantsAllowed
	oidcPasswordChecks = map[string]bool{}
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

type idpData struct {
	provider  runtime.Object
	challenge bool
	login     bool
}

func convertIdentityProviders(
	cmLister corelistersv1.ConfigMapLister,
	secretsLister corelistersv1.SecretLister,
	identityProviders []configv1.IdentityProvider,
) ([]interface{}, *datasync.ConfigSyncData, []error) {

	converted := []osinv1.IdentityProvider{}
	syncData := datasync.NewConfigSyncData()
	errs := []error{}

	for i, idp := range defaultIDPMappingMethods(identityProviders) {
		data, err := convertProviderConfigToIDPData(cmLister, secretsLister, &idp.IdentityProviderConfig, syncData, i)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to apply IDP %s config: %v", idp.Name, err))
			continue
		}
		converted = append(converted,
			osinv1.IdentityProvider{
				Name:            idp.Name,
				UseAsChallenger: data.challenge,
				UseAsLogin:      data.login,
				MappingMethod:   string(idp.MappingMethod),
				Provider: runtime.RawExtension{
					Raw: encodeOrDie(data.provider),
				},
			},
		)
	}

	// convert to json bytes and then store them in unstructured interface slice to
	// accomodate the observed config format
	convertedBytes, err := json.Marshal(converted)
	if err != nil {
		return nil, syncData, append(errs, err)
	}

	unstructuredIDPs := []interface{}{}
	if err := json.NewDecoder(bytes.NewBuffer(convertedBytes)).Decode(&unstructuredIDPs); err != nil {
		// this should not happen, the bytes were mashalled just a few lines above
		return nil, syncData, append(errs, fmt.Errorf("decode of observed config failed with error: %v", err))
	}

	return unstructuredIDPs, syncData, errs
}

func defaultIDPMappingMethods(identityProviders []configv1.IdentityProvider) []configv1.IdentityProvider {
	out := make([]configv1.IdentityProvider, len(identityProviders)) // do not mutate informer cache

	for i, idp := range identityProviders {
		idp.DeepCopyInto(&out[i])
		if out[i].MappingMethod == "" {
			out[i].MappingMethod = configv1.MappingMethodClaim
		}
	}

	return out
}

func convertProviderConfigToIDPData(
	cmLister corelistersv1.ConfigMapLister,
	secretsLister corelistersv1.SecretLister,
	providerConfig *configv1.IdentityProviderConfig,
	syncData *datasync.ConfigSyncData,
	i int,
) (*idpData, error) {
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
				CA:  syncData.AddIDPConfigMap(i, basicAuthConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: syncData.AddIDPSecret(i, basicAuthConfig.TLSClientCert, "tls-client-cert", corev1.TLSCertKey),
					KeyFile:  syncData.AddIDPSecret(i, basicAuthConfig.TLSClientKey, "tls-client-key", corev1.TLSPrivateKeyKey),
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
			ClientSecret:  createFileStringSource(syncData.AddIDPSecret(i, githubConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			Organizations: githubConfig.Organizations,
			Teams:         githubConfig.Teams,
			Hostname:      githubConfig.Hostname,
			CA:            syncData.AddIDPConfigMap(i, githubConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
		}
		data.challenge = false

	case configv1.IdentityProviderTypeGitLab:
		gitlabConfig := providerConfig.GitLab
		if gitlabConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.GitLabIdentityProvider{
			CA:           syncData.AddIDPConfigMap(i, gitlabConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
			URL:          gitlabConfig.URL,
			ClientID:     gitlabConfig.ClientID,
			ClientSecret: createFileStringSource(syncData.AddIDPSecret(i, gitlabConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
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
			ClientSecret: createFileStringSource(syncData.AddIDPSecret(i, googleConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			HostedDomain: googleConfig.HostedDomain,
		}
		data.challenge = false

	case configv1.IdentityProviderTypeHTPasswd:
		if providerConfig.HTPasswd == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.HTPasswdPasswordIdentityProvider{
			File: syncData.AddIDPSecret(i, providerConfig.HTPasswd.FileData, "file-data", configv1.HTPasswdDataKey),
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
				CA:  syncData.AddIDPConfigMap(i, keystoneConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: syncData.AddIDPSecret(i, keystoneConfig.TLSClientCert, "tls-client-cert", corev1.TLSCertKey),
					KeyFile:  syncData.AddIDPSecret(i, keystoneConfig.TLSClientKey, "tls-client-key", corev1.TLSPrivateKeyKey),
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
			BindPassword: createFileStringSource(syncData.AddIDPSecret(i, ldapConfig.BindPassword, "bind-password", configv1.BindPasswordKey)),
			Insecure:     ldapConfig.Insecure,
			CA:           syncData.AddIDPConfigMap(i, ldapConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
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

		urls, err := discoverOpenIDURLs(cmLister, openIDConfig.Issuer, corev1.ServiceAccountRootCAKey, openIDConfig.CA)
		if err != nil {
			return nil, err
		}

		groupClaims := make([]string, len(openIDConfig.Claims.Groups))
		for i, g := range openIDConfig.Claims.Groups {
			groupClaims[i] = string(g)
		}

		data.provider = &osinv1.OpenIDIdentityProvider{
			CA:                       syncData.AddIDPConfigMap(i, openIDConfig.CA, "ca", corev1.ServiceAccountRootCAKey),
			ClientID:                 openIDConfig.ClientID,
			ClientSecret:             createFileStringSource(syncData.AddIDPSecret(i, openIDConfig.ClientSecret, "client-secret", configv1.ClientSecretKey)),
			ExtraScopes:              openIDConfig.ExtraScopes,
			ExtraAuthorizeParameters: openIDConfig.ExtraAuthorizeParameters,
			URLs:                     *urls,
			Claims: osinv1.OpenIDClaims{
				// There is no longer a user-facing setting for ID as it is considered unsafe
				ID:                []string{configv1.UserIDClaim},
				PreferredUsername: openIDConfig.Claims.PreferredUsername,
				Name:              openIDConfig.Claims.Name,
				Email:             openIDConfig.Claims.Email,
				Groups:            groupClaims,
			},
		}

		// openshift CR validating in kube-apiserver does not allow
		// challenge-redirecting IdPs to be configured with OIDC so it is safe
		// to allow challenge-issuing flow if it's available on the OIDC side
		challengeFlowsAllowed, err := checkOIDCPasswordGrantFlow(
			cmLister,
			secretsLister,
			urls.Token,
			openIDConfig.ClientID,
			openIDConfig.CA,
			openIDConfig.ClientSecret,
		)
		if err != nil {
			return nil, fmt.Errorf("error attempting password grant flow: %v", err)
		}
		data.challenge = challengeFlowsAllowed

	case configv1.IdentityProviderTypeRequestHeader:
		requestHeaderConfig := providerConfig.RequestHeader
		if requestHeaderConfig == nil {
			return nil, fmt.Errorf(missingProviderFmt, providerConfig.Type)
		}

		data.provider = &osinv1.RequestHeaderIdentityProvider{
			LoginURL:                 requestHeaderConfig.LoginURL,
			ChallengeURL:             requestHeaderConfig.ChallengeURL,
			ClientCA:                 syncData.AddIDPConfigMap(i, requestHeaderConfig.ClientCA, "ca", corev1.ServiceAccountRootCAKey),
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

// discoverOpenIDURLs retrieves basic information about an OIDC server with hostname
// given by the `issuer` argument
func discoverOpenIDURLs(cmLister corelistersv1.ConfigMapLister, issuer, key string, ca configv1.ConfigMapNameReference) (*osinv1.OpenIDURLs, error) {
	issuer = strings.TrimRight(issuer, "/") // TODO make impossible via validation and remove

	wellKnown := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}

	rt, err := transport.TransportForCARef(cmLister, ca.Name, key)
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

func checkOIDCPasswordGrantFlow(
	cmLister corelistersv1.ConfigMapLister,
	secretsLister corelistersv1.SecretLister,
	tokenURL, clientID string,
	caRererence configv1.ConfigMapNameReference,
	clientSecretReference configv1.SecretNameReference,
) (bool, error) {
	secret, err := secretsLister.Secrets("openshift-config").Get(clientSecretReference.Name)
	if err != nil {
		return false, fmt.Errorf("couldn't get the referenced secret: %v", err)
	}

	// check whether we already attempted this not to send unneccessary login
	// requests against the provider
	if cachedResult, ok := oidcPasswordChecks[secret.ResourceVersion]; ok {
		klog.V(4).Info("using cached result for OIDC password grant check")
		return cachedResult, nil
	}

	clientSecret, ok := secret.Data["clientSecret"]
	if !ok || len(clientSecret) == 0 {
		return false, fmt.Errorf("the referenced secret does not contain a value for the 'clientSecret' key")
	}

	transport, err := transport.TransportForCARef(cmLister, caRererence.Name, corev1.ServiceAccountRootCAKey)
	if err != nil {
		return false, fmt.Errorf("couldn't get a transport for the referenced CA: %v", err)
	}

	// prepare the grant-checking query
	query := url.Values{}
	query.Add("client_id", clientID)
	query.Add("client_secret", string(clientSecret))
	query.Add("grant_type", "password")
	query.Add("scope", "openid") // "openid" is the minimal scope, it MUST be present in an OIDC authn request
	query.Add("username", "test")
	query.Add("password", "test")
	body := strings.NewReader(query.Encode())

	req, err := http.NewRequest("POST", tokenURL, body)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// explicitly set Accept to 'application/json' as that's the expected deserializable output
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		return false, fmt.Errorf("OIDC token endpoint returned server error %d (%s)", resp.StatusCode, tokenURL)
	}

	respJSON := json.NewDecoder(resp.Body)
	respMap := map[string]interface{}{}
	if err = respJSON.Decode(&respMap); err != nil {
		// only log the error, some OIDCs ignore/don't implement the Accept header
		// and respond with HTML in case they don't support password credential grants at all
		klog.Errorf("failed to JSON-decode the response from the OIDC server's token endpoint (%s): %v", tokenURL, err)
		oidcPasswordChecks[secret.ResourceVersion] = false
		return false, nil
	}

	if errVal, ok := respMap["error"]; ok {
		oidcPasswordChecks[secret.ResourceVersion] = errVal == "invalid_grant" // wrong password, but password grants allowed
	} else {
		_, ok = respMap["access_token"] // in case we managed to hit the correct user
		oidcPasswordChecks[secret.ResourceVersion] = ok
	}

	return oidcPasswordChecks[secret.ResourceVersion], nil
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
