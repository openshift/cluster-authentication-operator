package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/utils"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func (c *authOperator) handleOAuthConfig(
	operatorConfig *operatorv1.Authentication,
	route *routev1.Route,
	routerSecret *corev1.Secret,
	service *corev1.Service,
	consoleConfig *configv1.Console,
	infrastructureConfig *configv1.Infrastructure,
	apiServerConfig *configv1.APIServer,
) (
	*corev1.ConfigMap,
	*configSyncData,
	error,
) {
	oauthConfigNoDefaults, err := c.oauth.Get("cluster", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		oauthConfigNoDefaults, err = c.oauth.Create(&configv1.OAuth{
			ObjectMeta: defaultGlobalConfigMeta(),
		})
	}
	if err != nil {
		return nil, nil, err
	}
	oauthConfig := defaultOAuthConfig(oauthConfigNoDefaults)

	var accessTokenInactivityTimeoutSeconds *int32
	timeout := oauthConfig.Spec.TokenConfig.AccessTokenInactivityTimeoutSeconds
	switch {
	case timeout < 0:
		zero := int32(0)
		accessTokenInactivityTimeoutSeconds = &zero
	case timeout == 0:
		accessTokenInactivityTimeoutSeconds = nil
	case timeout > 0:
		accessTokenInactivityTimeoutSeconds = &timeout
	}

	syncData := newConfigSyncData()

	templates, err := c.handleBrandingTemplates(oauthConfig.Spec.Templates, syncData)
	if err != nil {
		return nil, nil, err
	}

	var errsIDP []error
	identityProviders := make([]osinv1.IdentityProvider, 0, len(oauthConfig.Spec.IdentityProviders))
	for i, idp := range oauthConfig.Spec.IdentityProviders {
		data, err := c.convertProviderConfigToIDPData(&idp.IdentityProviderConfig, &syncData, i)
		if err != nil {
			klog.Errorf("failed to honor IDP %#v: %v", idp, err)
			errsIDP = append(errsIDP, fmt.Errorf("failed to apply IDP %s config: %v", idp.Name, err))
			continue
		}
		identityProviders = append(identityProviders,
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
	handleDegraded(operatorConfig, "IdentityProviderConfig", v1helpers.NewMultiLineAggregate(errsIDP))

	assetPublicURL, corsAllowedOrigins := consoleToDeploymentData(consoleConfig)
	corsAllowedOrigins = append(corsAllowedOrigins, apiServerConfig.Spec.AdditionalCORSAllowedOrigins...)
	minTLSVersion, cipherSuites := getSecurityProfileCiphers(apiServerConfig.Spec.TLSSecurityProfile)

	cliConfig := &osinv1.OsinServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: fmt.Sprintf("0.0.0.0:%d", 6443),
					BindNetwork: "tcp",
					// we have valid serving certs provided by service-ca
					// this is our main server cert which is used if SNI does not match
					CertInfo: configv1.CertInfo{
						CertFile: "/var/config/system/secrets/v4-0-config-system-serving-cert/tls.crt",
						KeyFile:  "/var/config/system/secrets/v4-0-config-system-serving-cert/tls.key",
					},
					ClientCA:          "", // I think this can be left unset
					NamedCertificates: routerSecretToSNI(routerSecret),
					MinTLSVersion:     minTLSVersion,
					CipherSuites:      cipherSuites,
				},
				MaxRequestsInFlight:   1000,   // TODO this is a made up number
				RequestTimeoutSeconds: 5 * 60, // 5 minutes
			},
			CORSAllowedOrigins: corsAllowedOrigins,     // set console route as valid CORS (so JS can logout)
			AuditConfig:        configv1.AuditConfig{}, // TODO probably need this
			KubeClientConfig: configv1.KubeClientConfig{
				KubeConfig: "", // this should use in cluster config
				ConnectionOverrides: configv1.ClientConnectionOverrides{
					QPS:   400, // TODO figure out values
					Burst: 400,
				},
			},
		},
		OAuthConfig: osinv1.OAuthConfig{
			MasterCA:                    getMasterCA(), // we have valid serving certs provided by service-ca so we can use the service for loopback
			MasterURL:                   fmt.Sprintf("https://%s.%s.svc", service.Name, service.Namespace),
			MasterPublicURL:             fmt.Sprintf("https://%s", route.Spec.Host),
			LoginURL:                    infrastructureConfig.Status.APIServerURL,
			AssetPublicURL:              assetPublicURL, // set console route as valid 302 redirect for logout
			AlwaysShowProviderSelection: false,
			IdentityProviders:           identityProviders,
			GrantConfig: osinv1.GrantConfig{
				Method:               osinv1.GrantHandlerDeny, // force denial as this field must be set per OAuth client
				ServiceAccountMethod: osinv1.GrantHandlerPrompt,
			},
			SessionConfig: &osinv1.SessionConfig{
				SessionSecretsFile:   "/var/config/system/secrets/v4-0-config-system-session/v4-0-config-system-session",
				SessionMaxAgeSeconds: 5 * 60, // 5 minutes
				SessionName:          "ssn",
			},
			TokenConfig: osinv1.TokenConfig{
				AuthorizeTokenMaxAgeSeconds:         5 * 60, // 5 minutes
				AccessTokenMaxAgeSeconds:            oauthConfig.Spec.TokenConfig.AccessTokenMaxAgeSeconds,
				AccessTokenInactivityTimeoutSeconds: accessTokenInactivityTimeoutSeconds,
			},
			Templates: templates,
		},
	}

	cliConfigBytes := encodeOrDie(cliConfig)

	completeConfigBytes, err := resourcemerge.MergeProcessConfig(nil, cliConfigBytes, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to merge config with unsupportedConfigOverrides: %v", err)
	}

	// TODO update OAuth status
	return getCliConfigMap(completeConfigBytes), &syncData, nil
}

func getCliConfigMap(completeConfigBytes []byte) *corev1.ConfigMap {
	meta := utils.DefaultMetaOAuthServerResources()
	meta.Name = "v4-0-config-system-cliconfig"
	return &corev1.ConfigMap{
		ObjectMeta: meta,
		Data: map[string]string{
			"v4-0-config-system-cliconfig": string(completeConfigBytes),
		},
	}
}

func getMasterCA() *string {
	ca := "/var/config/system/configmaps/v4-0-config-system-service-ca/service-ca.crt" // need local var to be able to take address of it
	return &ca
}

func defaultOAuthConfig(oauthConfig *configv1.OAuth) *configv1.OAuth {
	out := oauthConfig.DeepCopy() // do not mutate informer cache

	for i := range out.Spec.IdentityProviders {
		if out.Spec.IdentityProviders[i].MappingMethod == "" {
			out.Spec.IdentityProviders[i].MappingMethod = configv1.MappingMethodClaim
		}
	}

	if out.Spec.TokenConfig.AccessTokenMaxAgeSeconds == 0 {
		out.Spec.TokenConfig.AccessTokenMaxAgeSeconds = 24 * 60 * 60 // 1 day
	}

	return out
}

// TODO: this is taken from lib-go and should go away once we start observing config
func getSecurityProfileCiphers(profile *configv1.TLSSecurityProfile) (string, []string) {
	var profileType configv1.TLSProfileType
	if profile == nil {
		profileType = configv1.TLSProfileIntermediateType
	} else {
		profileType = profile.Type
	}

	var profileSpec *configv1.TLSProfileSpec
	if profileType == configv1.TLSProfileCustomType {
		if profile.Custom != nil {
			profileSpec = &profile.Custom.TLSProfileSpec
		}
	} else {
		profileSpec = configv1.TLSProfiles[profileType]
	}

	// nothing found / custom type set but no actual custom spec
	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}

	// need to remap all Ciphers to their respective IANA names used by Go
	return string(profileSpec.MinTLSVersion), crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers)
}
