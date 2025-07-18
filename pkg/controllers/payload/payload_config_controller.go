package payload

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	routev1 "github.com/openshift/api/route/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions/route/v1"
	routev1lister "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(osinv1.GroupVersion) // TODO I think there is a better way to do this
)

func init() {
	utilruntime.Must(osinv1.Install(scheme))
}

// knownConditionNames lists all condition types used by this controller.
// These conditions are operated and defaulted by this controller.
// Any new condition used by this controller sync() loop should be listed here.
var knownConditionNames = sets.NewString(
	"OAuthConfigDegraded",
	"OAuthSessionSecretDegraded",
	"OAuthConfigRouteDegraded",
	"OAuthConfigIngressDegraded",
	"OAuthConfigServiceDegraded",
)

type payloadConfigController struct {
	controllerInstanceName string
	serviceLister          corev1lister.ServiceLister
	routeLister            routev1lister.RouteLister

	configMaps     corev1client.ConfigMapsGetter
	secrets        corev1client.SecretsGetter
	operatorClient v1helpers.OperatorClient

	authConfigChecker common.AuthConfigChecker
}

func NewPayloadConfigController(
	instanceName string,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	secrets corev1client.SecretsGetter,
	configMaps corev1client.ConfigMapsGetter,
	operatorClient v1helpers.OperatorClient,
	routeInformer routeinformer.RouteInformer,
	authConfigChecker common.AuthConfigChecker,
	recorder events.Recorder) factory.Controller {
	c := &payloadConfigController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "PayloadConfig"),
		serviceLister:          kubeInformersForTargetNamespace.Core().V1().Services().Lister(),
		routeLister:            routeInformer.Lister(),
		secrets:                secrets,
		configMaps:             configMaps,
		operatorClient:         operatorClient,
		authConfigChecker:      authConfigChecker,
	}
	return factory.New().
		WithInformers(
			kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Services().Informer(),
			kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
			routeInformer.Informer(),
			operatorClient.Informer(),
		).
		WithInformers(common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...).
		ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		WithSync(c.sync).
		ToController(c.controllerInstanceName, recorder.WithComponentSuffix("payload-config-controller"))
}

func (c *payloadConfigController) getAuthConfig() (*operatorv1.OperatorSpec, []operatorv1.OperatorCondition) {
	spec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return nil, []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetFailed",
				Message: fmt.Sprintf("Unable to get cluster authentication config: %v", err),
			},
		}
	}
	return spec, nil
}

func (c *payloadConfigController) getSessionSecret(ctx context.Context, recorder events.Recorder) []operatorv1.OperatorCondition {
	secret, err := c.secrets.Secrets("openshift-authentication").Get(ctx, "v4-0-config-system-session", metav1.GetOptions{})
	if err != nil || !isValidSessionSecret(secret) {
		klog.V(4).Infof("Failed to get session secret %q: %v (generating new random)", "v4-0-config-system-session", err)
		secret, err = randomSessionSecret()
		if err != nil {
			return []operatorv1.OperatorCondition{
				{
					Type:    "OAuthSessionSecretDegraded",
					Status:  operatorv1.ConditionTrue,
					Reason:  "GenerateFailed",
					Message: fmt.Sprintf("Failed to generate new session secret %q: %v", "v4-0-config-system-session", err),
				},
			}
		}
	}
	if _, _, err := resourceapply.ApplySecret(ctx, c.secrets, recorder, secret); err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthSessionSecretDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ApplyFailed",
				Message: fmt.Sprintf("Failed to apply session secret %q: %v", "v4-0-config-system-session", err),
			},
		}
	}
	return nil
}

func (c *payloadConfigController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return err
	} else if oidcAvailable {
		if err := c.removeOperands(ctx); err != nil {
			return err
		}

		// Server-Side-Apply with an empty operator status for the specific field manager
		// will effectively remove any conditions owned by it since the list type in the
		// API definition is 'map'
		return c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, applyoperatorv1.OperatorStatus())
	}

	foundConditions := []operatorv1.OperatorCondition{}
	foundConditions = append(foundConditions, c.getSessionSecret(ctx, syncContext.Recorder())...)

	route, routeConditions := common.GetOAuthServerRoute(c.routeLister, "OAuthConfigRoute")
	foundConditions = append(foundConditions, routeConditions...)

	service, serviceConditions := common.GetOAuthServerService(c.serviceLister, "OAuthConfigService")
	foundConditions = append(foundConditions, serviceConditions...)

	operatorConfig, operatorConfigConditions := c.getAuthConfig()
	foundConditions = append(foundConditions, operatorConfigConditions...)

	// we need route and service to be not nil
	if len(foundConditions) == 0 {
		oauthConfigConditions := c.handleOAuthConfig(ctx, operatorConfig, route, service, syncContext.Recorder())
		foundConditions = append(foundConditions, oauthConfigConditions...)
	}

	return common.ApplyControllerConditions(ctx, c.operatorClient, c.controllerInstanceName, knownConditionNames, foundConditions)
}

func (c *payloadConfigController) removeOperands(ctx context.Context) error {
	if err := c.secrets.Secrets("openshift-authentication").Delete(ctx, "v4-0-config-system-session", metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		return err
	}

	if err := c.configMaps.ConfigMaps("openshift-authentication").Delete(ctx, "v4-0-config-system-cliconfig", metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		return err
	}

	return nil
}

func (c *payloadConfigController) handleOAuthConfig(ctx context.Context, operatorSpec *operatorv1.OperatorSpec, route *routev1.Route, service *corev1.Service, recorder events.Recorder) []operatorv1.OperatorCondition {
	ca := "/var/config/system/configmaps/v4-0-config-system-service-ca/service-ca.crt"
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
			MasterCA:                    &ca, // we have valid serving certs provided by service-ca so we can use the service for loopback
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
		},
	}

	cliConfigBytes, err := runtime.Encode(encoder, cliConfig)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "EncodeFailed",
				Message: fmt.Sprintf("Failed to encode CLI config: %v", err),
			},
		}
	}

	observedConfig, err := common.UnstructuredConfigFrom(operatorSpec.ObservedConfig.Raw, configobservation.OAuthServerConfigPrefix)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetOAuthServerConfigFailed",
				Message: fmt.Sprintf("Unable to get oauth-server configuration: %v", err),
			},
		}
	}

	unsupportedConfig, err := common.UnstructuredConfigFrom(operatorSpec.UnsupportedConfigOverrides.Raw, configobservation.OAuthServerConfigPrefix)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "GetOAuthServerUnsupportedConfigFailed",
				Message: fmt.Sprintf("Unable to get oauth-server configuration: %v", err),
			},
		}
	}

	completeConfigBytes, err := resourcemerge.MergePrunedProcessConfig(&osinv1.OsinServerConfig{}, nil, cliConfigBytes, observedConfig, unsupportedConfig)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "MergeConfigFailed",
				Message: fmt.Sprintf("Failed to merge config with unsupportedConfigOverrides: %v", err),
			},
		}
	}

	expectedCLIConfig := getCliConfigMap(completeConfigBytes)

	_, _, err = resourceapply.ApplyConfigMap(ctx, c.configMaps, recorder, expectedCLIConfig)
	if err != nil {
		return []operatorv1.OperatorCondition{
			{
				Type:    "OAuthConfigDegraded",
				Status:  operatorv1.ConditionTrue,
				Reason:  "ApplyFailed",
				Message: fmt.Sprintf("Failed to apply CLI configuration %q: %v", expectedCLIConfig.Name, err),
			},
		}
	}

	return nil
}

func getCliConfigMap(completeConfigBytes []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "v4-0-config-system-cliconfig",
			Namespace: "openshift-authentication",
			Labels: map[string]string{
				"app": "oauth-openshift",
			},
			Annotations:     map[string]string{},
			OwnerReferences: nil, // TODO
		},
		Data: map[string]string{
			"v4-0-config-system-cliconfig": string(completeConfigBytes),
		},
	}
}

func (c *payloadConfigController) getExpectedSessionSecret(ctx context.Context) (*corev1.Secret, error) {
	secret, err := c.secrets.Secrets("openshift-authentication").Get(ctx, "v4-0-config-system-session", metav1.GetOptions{})
	if err != nil || !isValidSessionSecret(secret) {
		klog.V(4).Infof("failed to get secret %s: %v", "v4-0-config-system-session", err)
		generatedSessionSecret, err := randomSessionSecret()
		if err != nil {
			return nil, err
		}
		return generatedSessionSecret, nil
	}
	return secret, nil
}

func isValidSessionSecret(secret *corev1.Secret) bool {
	// TODO add more validation?
	if secret == nil {
		return false
	}
	var sessionSecretsBytes [][]byte
	for _, v := range secret.Data {
		sessionSecretsBytes = append(sessionSecretsBytes, v)
	}
	for _, ss := range sessionSecretsBytes {
		var sessionSecrets *osinv1.SessionSecrets
		err := json.Unmarshal(ss, &sessionSecrets)
		if err != nil {
			return false
		}
		for _, s := range sessionSecrets.Secrets {
			if len(s.Authentication) != 64 {
				return false
			}

			if len(s.Encryption) != 32 {
				return false
			}
		}
	}
	return true
}

func randomSessionSecret() (*corev1.Secret, error) {
	skey, err := newSessionSecretsJSON()
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "v4-0-config-system-session",
			Namespace: "openshift-authentication",
			Labels: map[string]string{
				"app": "oauth-openshift",
			},
			Annotations:     map[string]string{},
			OwnerReferences: nil, // TODO
		},
		Data: map[string][]byte{
			"v4-0-config-system-session": skey,
		},
	}, nil

}
func newSessionSecretsJSON() ([]byte, error) {
	const (
		sha256KeyLenBytes = sha256.BlockSize // max key size with HMAC SHA256
		aes256KeyLenBytes = 32               // max key size with AES (AES-256)
	)

	secrets := &osinv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "operatorv1client",
		},
		Secrets: []osinv1.SessionSecret{
			{
				Authentication: randomString(sha256KeyLenBytes), // 64 chars
				Encryption:     randomString(aes256KeyLenBytes), // 32 chars
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the session secret: %v", err) // should never happen
	}

	return secretsBytes, nil
}

// needs to be in lib-go
func randomBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

// randomString uses RawURLEncoding to ensure we do not get / characters or trailing ='s
func randomString(size int) string {
	// each byte (8 bits) gives us 4/3 base64 (6 bits) characters
	// we account for that conversion and add one to handle truncation
	b64size := base64.RawURLEncoding.DecodedLen(size) + 1
	// trim down to the original requested size since we added one above
	return base64.RawURLEncoding.EncodeToString(randomBytes(b64size))[:size]
}
