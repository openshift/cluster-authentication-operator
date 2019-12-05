package operator2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/configobservation"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"

	"github.com/openshift/cluster-authentication-operator/pkg/operator2/datasync"
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(osinv1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

func (c *authOperator) handleOAuthConfig(
	ctx context.Context,
	operatorConfig *operatorv1.Authentication,
	route *routev1.Route,
	service *corev1.Service,
	conditions *authConditions,
) (
	*corev1.ConfigMap,
	*datasync.ConfigSyncData,
	error,
) {
	oauthConfigNoDefaults, err := c.oauth.Get(ctx, "cluster", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		oauthConfigNoDefaults, err = c.oauth.Create(ctx, &configv1.OAuth{
			ObjectMeta: defaultGlobalConfigMeta(),
		}, metav1.CreateOptions{})
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

	syncData := datasync.NewConfigSyncData()

	templates, err := c.handleBrandingTemplates(ctx, oauthConfig.Spec.Templates, syncData)
	if err != nil {
		return nil, nil, err
	}

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
					ClientCA: "", // I think this can be left unset
				},
				MaxRequestsInFlight:   1000,   // TODO this is a made up number
				RequestTimeoutSeconds: 5 * 60, // 5 minutes
			},
			AuditConfig: configv1.AuditConfig{}, // TODO probably need this
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
			AlwaysShowProviderSelection: false,
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
	observedConfig, err := grabPrefixedConfig(operatorConfig.Spec.ObservedConfig.Raw, configobservation.OAuthServerConfigPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to grab oauth-server configuration: %v", err)
	}

	completeConfigBytes, err := resourcemerge.MergePrunedProcessConfig(&osinv1.OsinServerConfig{}, nil, cliConfigBytes, observedConfig, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to merge config with unsupportedConfigOverrides: %v", err)
	}

	// TODO update OAuth status
	return getCliConfigMap(completeConfigBytes), &syncData, nil
}

// grabPrefixedConfig returns the configuration from the operator's observedConfig field
// in the subtree given by the prefix
func grabPrefixedConfig(observedBytes []byte, prefix ...string) ([]byte, error) {
	if len(prefix) == 0 {
		return observedBytes, nil
	}

	prefixedConfig := map[string]interface{}{}
	if err := json.NewDecoder(bytes.NewBuffer(observedBytes)).Decode(&prefixedConfig); err != nil {
		klog.V(4).Infof("decode of existing config failed with error: %v", err)
	}

	actualConfig, _, err := unstructured.NestedFieldCopy(prefixedConfig, prefix...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(actualConfig)
}

func getCliConfigMap(completeConfigBytes []byte) *corev1.ConfigMap {
	meta := defaultMeta()
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

	if out.Spec.TokenConfig.AccessTokenMaxAgeSeconds == 0 {
		out.Spec.TokenConfig.AccessTokenMaxAgeSeconds = 24 * 60 * 60 // 1 day
	}

	return out
}

func encodeOrDie(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}
	return bytes
}
