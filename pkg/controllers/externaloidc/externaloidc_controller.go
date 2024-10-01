package externaloidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

var (
	cfgScheme         = runtime.NewScheme()
	codecs            = serializer.NewCodecFactory(cfgScheme, serializer.EnableStrict)
	serializerInfo, _ = runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
)

const (
	configNamespace           = "openshift-config"
	managedNamespace          = "openshift-config-managed"
	targetAuthConfigCMName    = "auth-config"
	authConfigDataKey         = "auth-config.json"
	oidcDiscoveryEndpointPath = "/.well-known/openid-configuration"
)

func init() {
	if err := apiserverv1beta1.AddToScheme(cfgScheme); err != nil {
		panic(err)
	}
}

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

	authConfig, err := c.generateAuthConfig(*auth)
	if err != nil {
		return err
	}

	encoded, err := runtime.Encode(codecs.EncoderForVersion(serializerInfo.Serializer, apiserverv1beta1.ConfigSchemeGroupVersion), authConfig)
	if err != nil {
		return fmt.Errorf("could not marshal auth config into JSON: %v", err)
	}
	authConfigJSON := strings.TrimSpace(string(encoded))

	existingCM, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not retrieve auth configmap %s/%s to check data before sync: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	if existingCM != nil && existingCM.Data[authConfigDataKey] == authConfigJSON {
		return nil
	}

	errList := validateAuthenticationConfiguration(*authConfig)
	if len(errList) > 0 {
		return fmt.Errorf("auth config validation failed: %v", errList)
	}

	cm := corev1ac.ConfigMap(targetAuthConfigCMName, managedNamespace).WithData(map[string]string{authConfigDataKey: authConfigJSON})
	if _, err := c.configMaps.ConfigMaps(managedNamespace).Apply(ctx, cm, metav1.ApplyOptions{FieldManager: c.name}); err != nil {
		return fmt.Errorf("could not apply changes to auth configmap %s/%s: %v", managedNamespace, targetAuthConfigCMName, err)
	}

	syncCtx.Recorder().Eventf(c.eventName, "Synced auth configmap %s/%s", managedNamespace, targetAuthConfigCMName)

	return nil
}

// generateAuthConfig creates a structured JWT AuthenticationConfiguration for OIDC
// from the configuration found in the authentication/cluster resource
func (c *externalOIDCController) generateAuthConfig(auth configv1.Authentication) (*apiserverv1beta1.AuthenticationConfiguration, error) {
	authConfig := apiserverv1beta1.AuthenticationConfiguration{}
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
			},
		}

		if len(provider.Issuer.Audiences) > 0 {
			jwt.Issuer.Audiences = make([]string, 0, len(provider.Issuer.Audiences))
			for _, aud := range provider.Issuer.Audiences {
				jwt.Issuer.Audiences = append(jwt.Issuer.Audiences, string(aud))
			}
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
		case configv1.NoOpinion:
			jwt.ClaimMappings.Username.Prefix = ptr.To("")
		case configv1.NoPrefix:
			jwt.ClaimMappings.Username.Prefix = ptr.To("-")
		case configv1.Prefix:
			if provider.ClaimMappings.Username.Prefix == nil {
				return nil, fmt.Errorf("nil username prefix while policy expects one")
			} else {
				jwt.ClaimMappings.Username.Prefix = &provider.ClaimMappings.Username.Prefix.PrefixString
			}
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

// validateAuthenticationConfiguration runs as many validations as possible
// on the AuthenticationConfiguration in order to catch validation errors early in the process
// instead of waiting for the KAS pods to roll out and consume the configuration
func validateAuthenticationConfiguration(auth apiserverv1beta1.AuthenticationConfiguration) (errs []error) {
	// TODO currently validations from k8s.io/apiserver/pkg/apis/apiserver/validation cannot be used here
	// since they aren't defined for the beta type; once the feature goes out of beta, we should replace
	// this func with the upstream validations (but keep CA cert validation)

	if len(auth.JWT) == 0 {
		errs = append(errs, fmt.Errorf("no JWT issuers defined"))
	}

	for _, jwt := range auth.JWT {
		var issuerURL *url.URL
		issuerURLValid := true
		if len(jwt.Issuer.URL) == 0 {
			errs = append(errs, fmt.Errorf("issuer URL must not be empty"))
			issuerURLValid = false
		} else {
			var err error
			issuerURL, err = url.Parse(jwt.Issuer.URL)
			if err != nil {
				errs = append(errs, err)
				issuerURLValid = false
			} else {
				if issuerURL.Scheme != "https" {
					errs = append(errs, fmt.Errorf("issuer URL must use HTTPS"))
					issuerURLValid = false
				}
				if issuerURL.User != nil {
					errs = append(errs, fmt.Errorf("URL must not contain a username or password"))
					issuerURLValid = false
				}
				if len(issuerURL.RawQuery) > 0 {
					errs = append(errs, fmt.Errorf("URL must not contain a query"))
					issuerURLValid = false
				}
				if len(issuerURL.Fragment) > 0 {
					errs = append(errs, fmt.Errorf("URL must not contain a fragment"))
					issuerURLValid = false
				}
			}
		}

		if len(jwt.Issuer.Audiences) == 0 {
			errs = append(errs, fmt.Errorf("at least one audience must be defined"))
		}
		seenAudiences := sets.NewString()
		for i, aud := range jwt.Issuer.Audiences {
			if len(aud) == 0 {
				errs = append(errs, fmt.Errorf("audience must not be empty (at index %d)", i))
			} else if seenAudiences.Has(aud) {
				errs = append(errs, fmt.Errorf("duplicate audience: %s", aud))
			}

			seenAudiences.Insert(aud)
		}

		var caCertPool *x509.CertPool
		caCertPoolValid := true
		if len(jwt.Issuer.CertificateAuthority) > 0 {
			var err error
			caCertPool, err = cert.NewPoolFromBytes([]byte(jwt.Issuer.CertificateAuthority))
			if err != nil {
				caCertPoolValid = false
				errs = append(errs, fmt.Errorf("issuer CA is invalid: %v", err))
			}
		}

		if issuerURL != nil && issuerURLValid && caCertPoolValid {
			// make sure we can access the issuer with the given cert pool (system CAs used if pool is empty)
			if err := validateCACert(*issuerURL, caCertPool); err != nil {
				certMessage := "using the specified CA cert"
				if caCertPool == nil {
					certMessage = "using the system CAs"
				}
				errs = append(errs, fmt.Errorf("could not validate IDP URL %s: %v", certMessage, err))
			}
		}

		seenClaims := sets.NewString()
		for i, rule := range jwt.ClaimValidationRules {
			if len(rule.Claim) == 0 {
				errs = append(errs, fmt.Errorf("claim must not be empty for claim validation rule at index %d", i))
			} else if seenClaims.Has(rule.Claim) {
				errs = append(errs, fmt.Errorf("duplicate claim validation rule: %s", rule.Claim))
			}

			seenClaims.Insert(rule.Claim)
		}

		if len(jwt.ClaimMappings.Username.Claim) == 0 {
			errs = append(errs, fmt.Errorf("username claim must not be empty"))
		} else if jwt.ClaimMappings.Username.Prefix == nil {
			errs = append(errs, fmt.Errorf("username prefix must not be nil when claim is set"))
		}

		if len(jwt.ClaimMappings.Groups.Claim) > 0 && jwt.ClaimMappings.Groups.Prefix == nil {
			errs = append(errs, fmt.Errorf("group prefix must not be nil when claim is set"))
		}
	}

	return
}

// validateCACert makes a request to the provider's well-known endpoint using the
// specified CA cert pool to validate that the certs in the pool match the host
func validateCACert(hostURL url.URL, caCertPool *x509.CertPool) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		},
		Timeout: 5 * time.Second,
	}

	wellKnown := strings.TrimSuffix(hostURL.String(), "/") + oidcDiscoveryEndpointPath
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
