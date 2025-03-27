package externaloidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"golang.org/x/net/http/httpproxy"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

const (
	configNamespace                 = "openshift-config"
	managedNamespace                = "openshift-config-managed"
	targetAuthConfigCMName          = "auth-config"
	authConfigDataKey               = "auth-config.json"
	oidcDiscoveryEndpointPath       = "/.well-known/openid-configuration"
	kindAuthenticationConfiguration = "AuthenticationConfiguration"
)

type externalOIDCController struct {
	name            string
	eventName       string
	authLister      configv1listers.AuthenticationLister
	configMapLister corev1listers.ConfigMapLister
	configMaps      corev1client.ConfigMapsGetter
}

func NewExternalOIDCController(
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	configMaps corev1client.ConfigMapsGetter,
	recorder events.Recorder,
) factory.Controller {

	c := &externalOIDCController{
		name:      "ExternalOIDCController",
		eventName: "external-oidc-controller",

		authLister:      configInformer.Config().V1().Authentications().Lister(),
		configMapLister: kubeInformersForNamespaces.ConfigMapLister(),
		configMaps:      configMaps,
	}

	return factory.New().WithInformers(
		// track openshift-config for changes to the provider's CA bundle
		kubeInformersForNamespaces.InformersFor(configNamespace).Core().V1().ConfigMaps().Informer(),
		// track auth resource
		configInformer.Config().V1().Authentications().Informer(),
	).WithFilteredEventsInformers(
		// track openshift-config-managed/auth-config cm in case it gets changed externally
		factory.NamesFilter(targetAuthConfigCMName),
		kubeInformersForNamespaces.InformersFor(managedNamespace).Core().V1().ConfigMaps().Informer(),
	).WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController(c.name, recorder.WithComponentSuffix(c.eventName))
}

func (c *externalOIDCController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	auth, err := c.authLister.Get("cluster")
	if err != nil {
		return fmt.Errorf("could not get authentication/cluster: %v", err)
	}

	if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		// auth type is "IntegratedOAuth", "" or "None"; delete structured auth configmap if it exists
		return c.deleteAuthConfig(ctx, syncCtx)
	}

	authConfig, err := c.generateAuthConfig(*auth)
	if err != nil {
		return err
	}

	expectedApplyConfig, err := getExpectedApplyConfig(*authConfig)
	if err != nil {
		return err
	}

	existingApplyConfig, err := c.getExistingApplyConfig()
	if err != nil {
		return err
	}

	if existingApplyConfig != nil && equality.Semantic.DeepEqual(existingApplyConfig.Data, expectedApplyConfig.Data) {
		return nil
	}

	if err := validateAuthConfig(*authConfig); err != nil {
		return fmt.Errorf("auth config validation failed: %v", err)
	}

	if _, err := c.configMaps.ConfigMaps(managedNamespace).Apply(ctx, expectedApplyConfig, metav1.ApplyOptions{FieldManager: c.name, Force: true}); err != nil {
		return fmt.Errorf("could not apply changes to auth configmap %s/%s: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	syncCtx.Recorder().Eventf(c.eventName, "Synced auth configmap %s/%s", managedNamespace, targetAuthConfigCMName)

	return nil
}

// deleteAuthConfig checks if the auth config ConfigMap exists in the managed namespace, and deletes it
// if it does; it returns an error if it encounters one.
func (c *externalOIDCController) deleteAuthConfig(ctx context.Context, syncCtx factory.SyncContext) error {
	if _, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName); errors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if err := c.configMaps.ConfigMaps(managedNamespace).Delete(ctx, targetAuthConfigCMName, metav1.DeleteOptions{}); err == nil {
		syncCtx.Recorder().Eventf(c.eventName, "Removed auth configmap %s/%s", managedNamespace, targetAuthConfigCMName)

	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not delete existing configmap %s/%s: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	return nil
}

// generateAuthConfig creates a structured JWT AuthenticationConfiguration for OIDC
// from the configuration found in the authentication/cluster resource.
func (c *externalOIDCController) generateAuthConfig(auth configv1.Authentication) (*apiserverv1beta1.AuthenticationConfiguration, error) {
	authConfig := apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       kindAuthenticationConfiguration,
			APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(),
		},
	}

	for _, provider := range auth.Spec.OIDCProviders {
		jwt := apiserverv1beta1.JWTAuthenticator{
			Issuer: apiserverv1beta1.Issuer{
				URL:                 provider.Issuer.URL,
				AudienceMatchPolicy: apiserverv1beta1.AudienceMatchPolicyMatchAny,
			},
			ClaimMappings: apiserverv1beta1.ClaimMappings{
				Username: apiserverv1beta1.PrefixedClaimOrExpression{
					Claim: provider.ClaimMappings.Username.Claim,
				},
				Groups: apiserverv1beta1.PrefixedClaimOrExpression{
					Claim:  provider.ClaimMappings.Groups.Claim,
					Prefix: &provider.ClaimMappings.Groups.Prefix,
				},
				UID: apiserverv1beta1.ClaimOrExpression{
					Claim: "sub",
				},
			},
		}

		for _, aud := range provider.Issuer.Audiences {
			jwt.Issuer.Audiences = append(jwt.Issuer.Audiences, string(aud))
		}

		if len(provider.Issuer.CertificateAuthority.Name) > 0 {
			caConfigMap, err := c.configMapLister.ConfigMaps(configNamespace).Get(provider.Issuer.CertificateAuthority.Name)
			if err != nil {
				return nil, fmt.Errorf("could not retrieve auth configmap %s/%s to check CA bundle: %v", configNamespace, provider.Issuer.CertificateAuthority.Name, err)
			}

			caData, ok := caConfigMap.Data["ca-bundle.crt"]
			if !ok || len(caData) == 0 {
				return nil, fmt.Errorf("configmap %s/%s key \"ca-bundle.crt\" missing or empty", configNamespace, provider.Issuer.CertificateAuthority.Name)
			}

			jwt.Issuer.CertificateAuthority = caData
		}

		switch provider.ClaimMappings.Username.PrefixPolicy {

		case configv1.Prefix:
			if provider.ClaimMappings.Username.Prefix == nil {
				return nil, fmt.Errorf("nil username prefix while policy expects one")
			} else {
				jwt.ClaimMappings.Username.Prefix = &provider.ClaimMappings.Username.Prefix.PrefixString
			}

		case configv1.NoPrefix:
			jwt.ClaimMappings.Username.Prefix = ptr.To("")

		case configv1.NoOpinion:
			prefix := ""
			if provider.ClaimMappings.Username.Claim != "email" {
				prefix = provider.Issuer.URL + "#"
			}
			jwt.ClaimMappings.Username.Prefix = &prefix

		default:
			return nil, fmt.Errorf("invalid username prefix policy: %s", provider.ClaimMappings.Username.PrefixPolicy)
		}

		for i, rule := range provider.ClaimValidationRules {
			if rule.RequiredClaim == nil {
				return nil, fmt.Errorf("empty validation rule at index %d", i)
			}

			jwt.ClaimValidationRules = append(jwt.ClaimValidationRules, apiserverv1beta1.ClaimValidationRule{
				Claim:         rule.RequiredClaim.Claim,
				RequiredValue: rule.RequiredClaim.RequiredValue,
			})
		}

		authConfig.JWT = append(authConfig.JWT, jwt)
	}

	return &authConfig, nil
}

// getExpectedApplyConfig serializes the input authConfig into JSON and creates an apply configuration
// for a configmap with the serialized authConfig in the right key.
func getExpectedApplyConfig(authConfig apiserverv1beta1.AuthenticationConfiguration) (*corev1ac.ConfigMapApplyConfiguration, error) {
	authConfigBytes, err := json.Marshal(authConfig)
	if err != nil {
		return nil, fmt.Errorf("could not marshal auth config into JSON: %v", err)
	}

	expectedCMApplyConfig := corev1ac.ConfigMap(targetAuthConfigCMName, managedNamespace).
		WithData(map[string]string{
			authConfigDataKey: string(authConfigBytes),
		})

	return expectedCMApplyConfig, nil
}

// getExistingApplyConfig checks if an authConfig configmap already exists, and returns an apply configuration
// that represents it if it does; it returns nil otherwise.
func (c *externalOIDCController) getExistingApplyConfig() (*corev1ac.ConfigMapApplyConfiguration, error) {
	existingCM, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName)
	if apierrors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("could not retrieve auth configmap %s/%s to check data before sync: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	existingCMApplyConfig, err := corev1ac.ExtractConfigMap(existingCM, c.name)
	if err != nil {
		return nil, fmt.Errorf("could not extract ConfigMap apply configuration: %v", err)
	}

	return existingCMApplyConfig, nil
}

// validateAuthConfig performs validations that are not done at the server-side,
// including validation that the provided CA cert (or system CAs if not specified) can be used for
// TLS cert verification.
func validateAuthConfig(auth apiserverv1beta1.AuthenticationConfiguration) error {
	for _, jwt := range auth.JWT {
		var caCertPool *x509.CertPool
		var err error
		if len(jwt.Issuer.CertificateAuthority) > 0 {
			caCertPool, err = cert.NewPoolFromBytes([]byte(jwt.Issuer.CertificateAuthority))
			if err != nil {
				return fmt.Errorf("issuer CA is invalid: %v", err)
			}
		}

		// make sure we can access the issuer with the given cert pool (system CAs used if pool is empty)
		if err := validateCACert(jwt.Issuer.URL, caCertPool); err != nil {
			certMessage := "using the specified CA cert"
			if caCertPool == nil {
				certMessage = "using the system CAs"
			}
			return fmt.Errorf("could not validate IDP URL %s: %v", certMessage, err)
		}
	}

	return nil
}

// validateCACert makes a request to the provider's well-known endpoint using the
// specified CA cert pool to validate that the certs in the pool match the host.
func validateCACert(hostURL string, caCertPool *x509.CertPool) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
			Proxy: func(*http.Request) (*url.URL, error) {
				if proxyConfig := httpproxy.FromEnvironment(); len(proxyConfig.HTTPSProxy) > 0 {
					return url.Parse(proxyConfig.HTTPSProxy)
				}
				return nil, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	wellKnown := strings.TrimSuffix(hostURL, "/") + oidcDiscoveryEndpointPath
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("could not create well-known HTTP request: %v", err)
	}

	var resp *http.Response
	var connErr error
	retryCtx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	retry.RetryOnConnectionErrors(retryCtx, func(ctx context.Context) (done bool, err error) {
		resp, connErr = client.Do(req)
		return connErr == nil, connErr
	})
	if connErr != nil {
		return fmt.Errorf("GET well-known error: %v", connErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unable to read response body; HTTP status: %s; error: %v", resp.Status, err)
		}

		return fmt.Errorf("unexpected well-known status code %s: %s", resp.Status, body)
	}

	return nil
}
