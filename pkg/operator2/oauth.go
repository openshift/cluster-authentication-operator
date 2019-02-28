package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"

	configv1 "github.com/openshift/api/config/v1"
	kubecontrolplanev1 "github.com/openshift/api/kubecontrolplane/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// TODO this code dies once we get our own CLI config
var (
	kubeControlplaneScheme  = runtime.NewScheme()
	kubeControlplaneCodecs  = serializer.NewCodecFactory(kubeControlplaneScheme)
	kubeControlplaneEncoder = kubeControlplaneCodecs.LegacyCodec(kubecontrolplanev1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(kubecontrolplanev1.Install(kubeControlplaneScheme))
}

func (c *authOperator) handleOAuthConfig(
	operatorConfig *operatorv1.Authentication,
	route *routev1.Route,
	service *corev1.Service,
	consoleConfig *configv1.Console,
) (
	*configv1.OAuth,
	*corev1.ConfigMap,
	*configSyncData,
	error,
) {
	oauthConfig, err := c.oauth.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, nil, nil, err
		}
		// did not find the object, use default
		oauthConfig = defaultOAuthConfig()
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

	// TODO this pretends this is an OsinServerConfig
	cliConfig := &kubecontrolplanev1.KubeAPIServerConfig{
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
		OAuthConfig: &osinv1.OAuthConfig{
			MasterCA: getMasterCA(), // we have valid serving certs provided by service-ca so we can use the service for loopback
			// TODO osin's code needs to be updated to properly use these values
			// it should use MasterURL in almost all places except the token request endpoint
			// which needs to direct the user to the real public URL (MasterPublicURL)
			// that means we still need to get that value from the installer's config
			// TODO ask installer team to make it easier to get that URL
			MasterURL:                   fmt.Sprintf("https://%s.%s.svc", service.Name, service.Namespace),
			MasterPublicURL:             fmt.Sprintf("https://%s", route.Spec.Host),
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

	cliConfigBytes := encodeOrDieKubeControlplane(cliConfig)

	completeConfigBytes, err := resourcemerge.MergeProcessConfig(nil, cliConfigBytes, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return nil, nil, nil, err
	}

	// TODO update OAuth status
	return oauthConfig, getCliConfigMap(completeConfigBytes), &syncData, nil
}

func defaultOAuthConfig() *configv1.OAuth {
	return &configv1.OAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name: globalConfigName,
		},
		Spec: configv1.OAuthSpec{
			TokenConfig: configv1.TokenConfig{
				AccessTokenMaxAgeSeconds: 86400,
			},
		},
	}
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

func encodeOrDieKubeControlplane(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(kubeControlplaneEncoder, obj)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}
	return bytes
}
