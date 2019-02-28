package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/golang/glog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

func (c *authOperator) handleOAuthConfig(
	operatorConfig *operatorv1.Authentication,
	route *routev1.Route,
	service *corev1.Service,
	consoleConfig *configv1.Console,
	infrastructureConfig *configv1.Infrastructure,
) (
	*configv1.OAuth,
	*corev1.ConfigMap,
	*configSyncData,
	error,
) {
	oauthConfig, err := c.oauth.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}

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

	var templates *osinv1.OAuthTemplates
	syncData := newConfigSyncData()

	emptyTemplates := configv1.OAuthTemplates{}
	if configTemplates := oauthConfig.Spec.Templates; configTemplates != emptyTemplates {
		templates = &osinv1.OAuthTemplates{
			Login:             syncData.AddTemplateSecret(configTemplates.Login, configv1.LoginTemplateKey),
			ProviderSelection: syncData.AddTemplateSecret(configTemplates.ProviderSelection, configv1.ProviderSelectionTemplateKey),
			Error:             syncData.AddTemplateSecret(configTemplates.Error, configv1.ErrorsTemplateKey),
		}
	}

	identityProviders := make([]osinv1.IdentityProvider, 0, len(oauthConfig.Spec.IdentityProviders))
	for i, idp := range oauthConfig.Spec.IdentityProviders {
		providerConfigBytes, err := convertProviderConfigToOsinBytes(&idp.IdentityProviderConfig, &syncData, i)
		if err != nil {
			glog.Error(err)
			continue
		}
		identityProviders = append(identityProviders,
			osinv1.IdentityProvider{
				Name:            idp.Name,
				UseAsChallenger: idp.UseAsChallenger,
				UseAsLogin:      idp.UseAsLogin,
				MappingMethod:   string(idp.MappingMethod),
				Provider: runtime.RawExtension{
					Raw: providerConfigBytes,
				},
			},
		)
	}

	assetPublicURL, corsAllowedOrigins := consoleToDeploymentData(consoleConfig)

	cliConfig := &osinv1.OsinServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: fmt.Sprintf("0.0.0.0:%d", containerPort),
					BindNetwork: "tcp4",
					// we have valid serving certs provided by service-ca so that we can use reencrypt routes
					CertInfo: configv1.CertInfo{
						CertFile: servingCertPathCert,
						KeyFile:  servingCertPathKey,
					},
					ClientCA:          "", // I think this can be left unset
					NamedCertificates: nil,
					MinTLSVersion:     crypto.TLSVersionToNameOrDie(crypto.DefaultTLSVersion()),
					CipherSuites:      crypto.CipherSuitesToNamesOrDie(crypto.DefaultCiphers()),
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
				Method:               osinv1.GrantHandlerPrompt, // TODO check
				ServiceAccountMethod: osinv1.GrantHandlerPrompt,
			},
			SessionConfig: &osinv1.SessionConfig{
				SessionSecretsFile:   sessionPath,
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
		return nil, nil, nil, err
	}

	// TODO update OAuth status
	return oauthConfig, getCliConfigMap(completeConfigBytes), &syncData, nil
}

func getCliConfigMap(completeConfigBytes []byte) *corev1.ConfigMap {
	meta := defaultMeta()
	meta.Name = cliConfigNameAndKey
	return &corev1.ConfigMap{
		ObjectMeta: meta,
		Data: map[string]string{
			cliConfigNameAndKey: string(completeConfigBytes),
		},
	}
}

func getMasterCA() *string {
	ca := serviceCAPath // need local var to be able to take address of it
	return &ca
}
