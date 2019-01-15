package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(osinv1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

func convertProviderConfigToOsinBytes(providerConfig *configv1.IdentityProviderConfig, syncData []idpSyncData, i int) ([]byte, error) {
	// FIXME: we need validation to make sure each of the IdP fields in each case is not nil!

	var p runtime.Object

	switch providerConfig.Type {
	case configv1.IdentityProviderTypeBasicAuth:
		basicAuthConfig := providerConfig.BasicAuth
		p = &osinv1.BasicAuthPasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: basicAuthConfig.URL,
				CA:  getFilenameFromConfigMapNameRef(syncData, i, basicAuthConfig.CA, corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: getFilenameFromSecretNameRef(syncData, i, basicAuthConfig.TLSClientCert, corev1.TLSCertKey),
					KeyFile:  getFilenameFromSecretNameRef(syncData, i, basicAuthConfig.TLSClientKey, corev1.TLSPrivateKeyKey),
				},
			},
		}

	case configv1.IdentityProviderTypeGitHub:
		githubConfig := providerConfig.GitHub
		p = &osinv1.GitHubIdentityProvider{
			ClientID:      githubConfig.ClientID,
			ClientSecret:  moveSecretFromRefToFileStringSource(syncData, i, githubConfig.ClientSecret, configv1.ClientSecretKey),
			Organizations: githubConfig.Organizations,
			Hostname:      githubConfig.Hostname,
			CA:            getFilenameFromConfigMapNameRef(syncData, i, githubConfig.CA, corev1.ServiceAccountRootCAKey),
		}

	case configv1.IdentityProviderTypeGitLab:
		gitlabConfig := providerConfig.GitLab
		p = &osinv1.GitLabIdentityProvider{
			CA:           getFilenameFromConfigMapNameRef(syncData, i, gitlabConfig.CA, corev1.ServiceAccountRootCAKey),
			URL:          gitlabConfig.URL,
			ClientID:     gitlabConfig.ClientID,
			ClientSecret: moveSecretFromRefToFileStringSource(syncData, i, gitlabConfig.ClientSecret, configv1.ClientSecretKey),
			Legacy:       new(bool), // we require OIDC for GitLab now
		}

	case configv1.IdentityProviderTypeGoogle:
		googleConfig := providerConfig.Google
		p = &osinv1.GoogleIdentityProvider{
			ClientID:     googleConfig.ClientID,
			ClientSecret: moveSecretFromRefToFileStringSource(syncData, i, googleConfig.ClientSecret, configv1.ClientSecretKey),
			HostedDomain: googleConfig.HostedDomain,
		}

	case configv1.IdentityProviderTypeHTPasswd:
		p = &osinv1.HTPasswdPasswordIdentityProvider{
			File: getFilenameFromSecretNameRef(syncData, i, providerConfig.HTPasswd.FileData, configv1.HTPasswdDataKey),
		}

	case configv1.IdentityProviderTypeKeystone:
		keystoneConfig := providerConfig.Keystone
		p = &osinv1.KeystonePasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: keystoneConfig.URL,
				CA:  getFilenameFromConfigMapNameRef(syncData, i, keystoneConfig.CA, corev1.ServiceAccountRootCAKey),
				CertInfo: configv1.CertInfo{
					CertFile: getFilenameFromSecretNameRef(syncData, i, keystoneConfig.TLSClientCert, corev1.TLSCertKey),
					KeyFile:  getFilenameFromSecretNameRef(syncData, i, keystoneConfig.TLSClientKey, corev1.TLSPrivateKeyKey),
				},
			},
			DomainName:          keystoneConfig.DomainName,
			UseKeystoneIdentity: !keystoneConfig.UseUsernameIdentity, // TODO if we are not upgrading from 3.11, then we can drop this config all together
		}

	case configv1.IdentityProviderTypeLDAP:
		ldapConfig := providerConfig.LDAP
		p = &osinv1.LDAPPasswordIdentityProvider{
			URL:          ldapConfig.URL,
			BindDN:       ldapConfig.BindDN,
			BindPassword: moveSecretFromRefToFileStringSource(syncData, i, ldapConfig.BindPassword, configv1.BindPasswordKey),
			Insecure:     ldapConfig.Insecure,
			CA:           getFilenameFromConfigMapNameRef(syncData, i, ldapConfig.CA, corev1.ServiceAccountRootCAKey),
		}

	case configv1.IdentityProviderTypeOpenID:
		openIDConfig := providerConfig.OpenID
		p = &osinv1.OpenIDIdentityProvider{
			CA:                       getFilenameFromConfigMapNameRef(syncData, i, openIDConfig.CA, corev1.ServiceAccountRootCAKey),
			ClientID:                 openIDConfig.ClientID,
			ClientSecret:             moveSecretFromRefToFileStringSource(syncData, i, openIDConfig.ClientSecret, configv1.ClientSecretKey),
			ExtraScopes:              openIDConfig.ExtraScopes,
			ExtraAuthorizeParameters: openIDConfig.ExtraAuthorizeParameters,
			URLs: osinv1.OpenIDURLs{
				Authorize: openIDConfig.URLs.Authorize,
				Token:     openIDConfig.URLs.Token,
				UserInfo:  openIDConfig.URLs.UserInfo,
			},
			Claims: osinv1.OpenIDClaims{
				// There is no longer a user-facing setting for ID as it is considered unsafe
				ID:                []string{configv1.UserIDClaim},
				PreferredUsername: openIDConfig.Claims.PreferredUsername,
				Name:              openIDConfig.Claims.Name,
				Email:             openIDConfig.Claims.Email,
			},
		}

	case configv1.IdentityProviderTypeRequestHeader:
		requestHeaderConfig := providerConfig.RequestHeader
		p = &osinv1.RequestHeaderIdentityProvider{
			LoginURL:                 requestHeaderConfig.LoginURL,
			ChallengeURL:             requestHeaderConfig.ChallengeURL,
			ClientCA:                 getFilenameFromConfigMapNameRef(syncData, i, requestHeaderConfig.ClientCA, corev1.ServiceAccountRootCAKey),
			ClientCommonNames:        requestHeaderConfig.ClientCommonNames,
			Headers:                  requestHeaderConfig.Headers,
			PreferredUsernameHeaders: requestHeaderConfig.PreferredUsernameHeaders,
			NameHeaders:              requestHeaderConfig.NameHeaders,
			EmailHeaders:             requestHeaderConfig.EmailHeaders,
		}

	default:
		return nil, fmt.Errorf("the identity provider type '%s' is not supported", providerConfig.Type)
	} // switch

	return encodeOrDie(p), nil
}

func createDenyAllIdentityProvider() osinv1.IdentityProvider {
	return osinv1.IdentityProvider{
		Name:            "defaultDenyAll",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider: runtime.RawExtension{
			Raw: encodeOrDie(&osinv1.DenyAllPasswordIdentityProvider{}),
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
