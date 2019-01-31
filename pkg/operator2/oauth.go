package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"

	configv1 "github.com/openshift/api/config/v1"
	kubecontrolplanev1 "github.com/openshift/api/kubecontrolplane/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	authv1alpha1 "github.com/openshift/cluster-authentication-operator/pkg/apis/authentication/v1alpha1"
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
	operatorConfig *authv1alpha1.AuthenticationOperatorConfig,
	route *routev1.Route,
	service *corev1.Service,
) (
	*configv1.OAuth,
	*configv1.Console,
	*corev1.ConfigMap,
	*idpSyncData,
	error,
) {
	oauthConfig, err := c.oauth.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// technically this should be an observed config loop
	consoleConfig, err := c.console.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		// FIXME: fix when the console team starts using this
		consoleConfig = &configv1.Console{}
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
	emptyTemplates := configv1.OAuthTemplates{}
	if oauthConfig.Spec.Templates != emptyTemplates {
		templates = &osinv1.OAuthTemplates{
			Login:             "", // TODO fix
			ProviderSelection: "", // TODO fix
			Error:             "", // TODO fix
		}
	}

	identityProviders := make([]osinv1.IdentityProvider, 0, len(oauthConfig.Spec.IdentityProviders))
	syncData := newIDPSyncData()
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
	if len(identityProviders) == 0 {
		identityProviders = []osinv1.IdentityProvider{
			createDenyAllIdentityProvider(),
		}
	}

	// TODO maybe move the OAuth stuff up one level
	err = c.handleConfigSync(&syncData)
	if err != nil {
		return nil, nil, nil, nil, err
	}

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
			CORSAllowedOrigins: nil,                    // TODO probably need this
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
			AssetPublicURL:              consoleConfig.Status.PublicHostname, // set console route as valid 302 redirect for logout
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
		return nil, nil, nil, nil, err
	}

	// TODO update OAuth status
	return oauthConfig, consoleConfig, getCliConfigMap(completeConfigBytes), &syncData, nil
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
