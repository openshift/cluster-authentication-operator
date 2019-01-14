package operator2

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/golang/glog"

	configv1 "github.com/openshift/api/config/v1"
	kubecontrolplanev1 "github.com/openshift/api/kubecontrolplane/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

const (
	defaultAccessTokenMaxAgeSeconds            = 24 * 60 * 60 // 1 day
	defaultAccessTokenInactivityTimeoutSeconds = 5 * 60       // 5 min
)

func defaultOAuth(name string) *configv1.OAuth {
	return &configv1.OAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: defaultLabels(),
			Annotations: map[string]string{
				// TODO - better annotations & messaging to user about defaulting behavior
				"message": "Default OAuth created by cluster-authentication-operator",
			},
		},
		Spec: configv1.OAuthSpec{
			IdentityProviders: []configv1.IdentityProvider{},
			TokenConfig: configv1.TokenConfig{
				AccessTokenMaxAgeSeconds:            defaultAccessTokenMaxAgeSeconds,
				AccessTokenInactivityTimeoutSeconds: defaultAccessTokenInactivityTimeoutSeconds,
			},
		},
		Status: configv1.OAuthStatus{},
	}

}
func (c *authOperator) fetchOAuthConfig() (*configv1.OAuth, error) {
	// Fetch any existing OAuth instance
	glog.V(5).Infof("fetching authentication resource '%s'", c.configName)
	existing, err := c.oauth.Get(c.configName, metav1.GetOptions{})
	if err == nil || !apierrors.IsNotFound(err) {
		// Existing instance found, or unknown error from api
		return existing, err
	}
	// No existing instance found; attempt to create default
	glog.V(5).Infof("creating default oauth resource '%s'", c.configName)
	created, err := c.oauth.Create(defaultOAuth(c.configName))
	if err == nil || !apierrors.IsAlreadyExists(err) {
		// Created successfully, or unknown error from api
		return created, err
	}
	// An OAuth instance must have been created between when we
	// first checked and when we attempted to create the default.
	// Find the existing instance, returning any errors trying to fetch it
	glog.V(5).Infof("re-fetching oauth resource '%s'", c.configName)
	return c.oauth.Get(c.configName, metav1.GetOptions{})
}

func (c *authOperator) configMapForOAuth(oauthConfig *configv1.OAuth, route *routev1.Route, configOverrides []byte) (*corev1.ConfigMap, error) {
	if oauthConfig == nil {
		return nil, nil
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
			Login:             getFilenameFromSecretNameRef(oauthConfig.Spec.Templates.Login),
			ProviderSelection: getFilenameFromSecretNameRef(oauthConfig.Spec.Templates.ProviderSelection),
			Error:             getFilenameFromSecretNameRef(oauthConfig.Spec.Templates.Error),
		}
	}

	identityProviders := make([]osinv1.IdentityProvider, 0, len(oauthConfig.Spec.IdentityProviders))
	for _, idp := range oauthConfig.Spec.IdentityProviders {
		providerConfigBytes, err := convertProviderConfigToOsinBytes(&idp.ProviderConfig)
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
					Raw:    providerConfigBytes,
					Object: nil, // grant config is incorrectly in the IDP, but should be dropped in general
				}, // TODO also need a series of config maps and secrets mounts based on this
			},
		)
	}
	if len(identityProviders) == 0 {
		identityProviders = []osinv1.IdentityProvider{
			createDenyAllIdentityProvider(),
		}
	}

	// TODO this pretends this is an OsinServerConfig
	cliConfig := &kubecontrolplanev1.KubeAPIServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: "0.0.0.0:443",
					BindNetwork: "tcp4",
					CertInfo: configv1.CertInfo{
						CertFile: "", // needs to be signed by MasterCA from below
						KeyFile:  "",
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
			// TODO at the very least this needs to be set to self signed loopback CA for the token request endpoint
			MasterCA: nil,
			// TODO osin's code needs to be updated to properly use these values
			// it should use MasterURL in almost all places except the token request endpoint
			// which needs to direct the user to the real public URL (MasterPublicURL)
			// that means we still need to get that value from the installer's config
			// TODO ask installer team to make it easier to get that URL
			MasterURL:                   fmt.Sprintf("https://%s", route.Spec.Host),
			MasterPublicURL:             fmt.Sprintf("https://%s", route.Spec.Host),
			AssetPublicURL:              "", // TODO do we need this?
			AlwaysShowProviderSelection: false,
			IdentityProviders:           identityProviders,
			GrantConfig: osinv1.GrantConfig{
				Method:               osinv1.GrantHandlerPrompt, // TODO check
				ServiceAccountMethod: osinv1.GrantHandlerPrompt,
			},
			SessionConfig: &osinv1.SessionConfig{
				SessionSecretsFile:   fmt.Sprintf("%s/%s", sessionPath, sessionKey),
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

	cliConfigBytes, err := json.Marshal(cliConfig)
	if err != nil {
		return nil, err
	}

	completeConfigBytes, err := resourcemerge.MergeProcessConfig(nil, cliConfigBytes, configOverrides)
	if err != nil {
		return nil, err
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.targetName,
			Namespace: c.targetNamespace,
			Labels:    defaultLabels(),
		},
		Data: map[string]string{
			configKey: string(completeConfigBytes),
		},
	}, nil
}
