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
	configscheme "github.com/openshift/client-go/config/clientset/versioned/scheme"
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
	managedConsoleConfig *corev1.ConfigMap,
) (
	*configv1.OAuth,
	*corev1.ConfigMap,
	*configSyncData,
	error,
) {
	oauthConfigNoDefaults, err := c.oauth.Get(globalConfigName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		oauthConfigNoDefaults, err = c.oauth.Create(&configv1.OAuth{
			ObjectMeta: defaultGlobalConfigMeta(),
		})
	}
	if err != nil {
		return nil, nil, nil, err
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

	var templates *osinv1.OAuthTemplates
	syncData := newConfigSyncData()

	emptyTemplates := configv1.OAuthTemplates{}
	if configTemplates := oauthConfig.Spec.Templates; configTemplates != emptyTemplates {
		templates = &osinv1.OAuthTemplates{
			Login:             syncData.addTemplateSecret(configTemplates.Login, loginField, configv1.LoginTemplateKey),
			ProviderSelection: syncData.addTemplateSecret(configTemplates.ProviderSelection, providerSelectionField, configv1.ProviderSelectionTemplateKey),
			Error:             syncData.addTemplateSecret(configTemplates.Error, errorField, configv1.ErrorsTemplateKey),
		}
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
	if err := v1helpers.NewMultiLineAggregate(errsIDP); err != nil {
		setDegradedTrue(operatorConfig, "IdentityProviderConfigError", err.Error())
	}

	assetPublicURL, corsAllowedOrigins := consoleToDeploymentData(consoleConfig)

	cliConfig := &osinv1.OsinServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: fmt.Sprintf("0.0.0.0:%d", containerPort),
					BindNetwork: "tcp4",
					// we have valid serving certs provided by service-ca
					// this is our main server cert which is used if SNI does not match
					CertInfo: configv1.CertInfo{
						CertFile: servingCertPathCert,
						KeyFile:  servingCertPathKey,
					},
					ClientCA:          "", // I think this can be left unset
					NamedCertificates: routerSecretToSNI(routerSecret),
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
				Method:               osinv1.GrantHandlerDeny, // force denial as this field must be set per OAuth client
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

	newConsoleConfig, err := managedConsoleConfigBytes(managedConsoleConfig)
	if err != nil {
		klog.Warningf("managed console config is not in the right format: %v", err)
	}

	completeConfigBytes, err := resourcemerge.MergeProcessConfig(nil, cliConfigBytes, newConsoleConfig, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to merge oauthConfig, managedConsoleConfig, and unsupportedConfigOverrides: %v", err)
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

func managedConsoleConfigBytes(managedConsoleConfig *corev1.ConfigMap) ([]byte, error) {
	data := managedConsoleConfig.Data
	var objBytes []byte
	for _, v := range data {
		objBytes = []byte(v)
	}
	if objBytes != nil {
		console := &configv1.Console{}
		err := runtime.DecodeInto(configscheme.Codecs.UniversalDecoder(configv1.SchemeGroupVersion), objBytes, console)
		if err != nil {
			return []byte{}, err
		}
		return objBytes, nil
	}
	return []byte{}, nil
}
