package operator2

import (
	"bufio"
	"bytes"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	kubejson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

func convertProviderConfigToOsinBytes(providerConfig *configv1.IdentityProviderConfig) ([]byte, error) {
	// FIXME: we need validation to make sure each of the IdP fields in each case is not nil!
	var providerConfigBytes bytes.Buffer

	bytesWriter := bufio.NewWriter(&providerConfigBytes)
	serializer := kubejson.NewYAMLSerializer(kubejson.DefaultMetaFactory, scheme, scheme)

	switch providerConfig.Type {
	case configv1.IdentityProviderTypeBasicAuth:
		basicAuthConfig := providerConfig.BasicAuth
		p := osinv1.BasicAuthPasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: basicAuthConfig.URL,
				CA:  getFilenameFromConfigMapNameRef(basicAuthConfig.CA),
				CertInfo: configv1.CertInfo{
					CertFile: getFilenameFromSecretNameRef(basicAuthConfig.TLSClientCert),
					KeyFile:  getFilenameFromSecretNameRef(basicAuthConfig.TLSClientKey),
				},
			},
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeGitHub:
		githubConfig := providerConfig.GitHub
		p := osinv1.GitHubIdentityProvider{
			ClientID:      githubConfig.ClientID,
			ClientSecret:  moveSecretFromRefToFileStringSource(githubConfig.ClientSecret),
			Organizations: githubConfig.Organizations,
			Hostname:      githubConfig.Hostname,
			CA:            getFilenameFromConfigMapNameRef(githubConfig.CA),
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeGitLab:
		gitlabConfig := providerConfig.GitLab
		p := osinv1.GitLabIdentityProvider{
			CA:           getFilenameFromConfigMapNameRef(gitlabConfig.CA),
			URL:          gitlabConfig.URL,
			ClientID:     gitlabConfig.ClientID,
			ClientSecret: moveSecretFromRefToFileStringSource(gitlabConfig.ClientSecret),
			Legacy:       new(bool), // we require OIDC for GitLab now
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeGoogle:
		googleConfig := providerConfig.Google
		p := osinv1.GoogleIdentityProvider{
			ClientID:     googleConfig.ClientID,
			ClientSecret: moveSecretFromRefToFileStringSource(googleConfig.ClientSecret),
			HostedDomain: googleConfig.HostedDomain,
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeHTPasswd:
		p := osinv1.HTPasswdPasswordIdentityProvider{
			File: getFilenameFromSecretNameRef(providerConfig.HTPasswd.FileData),
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeKeystone:
		keystoneConfig := providerConfig.Keystone
		p := osinv1.KeystonePasswordIdentityProvider{
			RemoteConnectionInfo: configv1.RemoteConnectionInfo{
				URL: keystoneConfig.URL,
				CA:  getFilenameFromConfigMapNameRef(keystoneConfig.CA),
				CertInfo: configv1.CertInfo{
					CertFile: getFilenameFromSecretNameRef(keystoneConfig.TLSClientCert),
					KeyFile:  getFilenameFromSecretNameRef(keystoneConfig.TLSClientKey),
				},
			},
			DomainName:          keystoneConfig.DomainName,
			UseKeystoneIdentity: !keystoneConfig.UseUsernameIdentity,
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeLDAP:
		ldapConfig := providerConfig.LDAP
		p := osinv1.LDAPPasswordIdentityProvider{
			URL:          ldapConfig.URL,
			BindDN:       ldapConfig.BindDN,
			BindPassword: moveSecretFromRefToFileStringSource(ldapConfig.BindPassword),
			Insecure:     ldapConfig.Insecure,
			CA:           getFilenameFromConfigMapNameRef(ldapConfig.CA),
		}
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeOpenID:
		openIDConfig := providerConfig.OpenID
		p := osinv1.OpenIDIdentityProvider{
			CA:                       getFilenameFromConfigMapNameRef(openIDConfig.CA),
			ClientID:                 openIDConfig.ClientID,
			ClientSecret:             moveSecretFromRefToFileStringSource(openIDConfig.ClientSecret),
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
		serializer.Encode(&p, bytesWriter)

	case configv1.IdentityProviderTypeRequestHeader:
		requestHeaderConfig := providerConfig.RequestHeader
		p := osinv1.RequestHeaderIdentityProvider{
			LoginURL:                 requestHeaderConfig.LoginURL,
			ChallengeURL:             requestHeaderConfig.ChallengeURL,
			ClientCA:                 getFilenameFromConfigMapNameRef(requestHeaderConfig.ClientCA),
			ClientCommonNames:        requestHeaderConfig.ClientCommonNames,
			Headers:                  requestHeaderConfig.Headers,
			PreferredUsernameHeaders: requestHeaderConfig.PreferredUsernameHeaders,
			NameHeaders:              requestHeaderConfig.NameHeaders,
			EmailHeaders:             requestHeaderConfig.EmailHeaders,
		}
		serializer.Encode(&p, bytesWriter)

	default:
		return nil, fmt.Errorf("the identity provider type '%s' is not supported", providerConfig.Type)
	} // switch

	bytesWriter.Flush()
	return providerConfigBytes.Bytes(), nil
}

func createDenyAllIdentityProvider() osinv1.IdentityProvider {
	var providerConfigBytes bytes.Buffer

	bytesWriter := bufio.NewWriter(&providerConfigBytes)
	serializer := kubejson.NewYAMLSerializer(kubejson.DefaultMetaFactory, scheme, scheme)

	serializer.Encode(&osinv1.DenyAllPasswordIdentityProvider{}, bytesWriter)
	bytesWriter.Flush()

	return osinv1.IdentityProvider{
		Name:            "defaultDenyAll",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider: runtime.RawExtension{
			Raw:    providerConfigBytes.Bytes(),
			Object: nil,
		},
	}
}
