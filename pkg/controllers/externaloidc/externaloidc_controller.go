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
	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

const (
	caBundleConfigMapNamespace = "openshift-config"
	targetConfigMapNamespace   = "openshift-config-managed"
	targetAuthConfigCMName     = "auth-config"
	authConfigDataKey          = "auth-config.json"
)

type externalOIDCController struct {
	name                string
	eventName           string
	featureGateAccessor featuregates.FeatureGateAccess
	authLister          configv1listers.AuthenticationLister
	configMapLister     corev1listers.ConfigMapLister
	configMaps          corev1client.ConfigMapsGetter
}

func NewExternalOIDCController(
	featureGateAccessor featuregates.FeatureGateAccess,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	configMaps corev1client.ConfigMapsGetter,
	recorder events.Recorder,
) factory.Controller {

	c := &externalOIDCController{
		name:      "ExternalOIDCController",
		eventName: "external-oidc-controller",

		featureGateAccessor: featureGateAccessor,
		authLister:          configInformer.Config().V1().Authentications().Lister(),
		configMapLister:     kubeInformersForNamespaces.ConfigMapLister(),
		configMaps:          configMaps,
	}

	return factory.New().WithInformers(
		// track openshift-config for changes to the provider's CA bundle
		kubeInformersForNamespaces.InformersFor(caBundleConfigMapNamespace).Core().V1().ConfigMaps().Informer(),
		// track auth resource
		configInformer.Config().V1().Authentications().Informer(),
	).WithFilteredEventsInformers(
		factory.NamesFilter(targetAuthConfigCMName),
		kubeInformersForNamespaces.InformersFor(targetConfigMapNamespace).Core().V1().ConfigMaps().Informer(),
	).WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		ToController(c.name, recorder.WithComponentSuffix(c.eventName))
}

func (c *externalOIDCController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if c.featureGateAccessor == nil || !c.featureGateAccessor.AreInitialFeatureGatesObserved() {
		return nil
	}

	featureGates, err := c.featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return fmt.Errorf("could not get current feature gates: %v", err)
	}

	if !featureGates.Enabled(features.FeatureGateExternalOIDC) {
		return nil
	}

	auth, err := c.authLister.Get("cluster")
	if err != nil {
		return fmt.Errorf("could not get authentication/cluster: %v", err)
	}

	if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		// auth type is "IntegratedOAuth", "" or "None"; delete structured auth configmap if it exists
		if err := c.configMaps.ConfigMaps(targetConfigMapNamespace).Delete(ctx, targetAuthConfigCMName, metav1.DeleteOptions{}); err == nil {
			syncCtx.Recorder().Eventf(c.eventName, "Removed auth configmap %s/%s", targetConfigMapNamespace, targetAuthConfigCMName)

		} else if !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not delete existing configmap %s/%s: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
		}

		return nil
	}

	// generate structured auth configmap and sync it into the target namespace
	authConfig, err := c.generateAuthConfig(*auth)
	if err != nil {
		return err
	}

	authConfigJSON, err := json.Marshal(authConfig)
	if err != nil {
		return fmt.Errorf("could not marshal auth config into JSON: %v", err)
	}

	existingCM, err := c.configMapLister.ConfigMaps(targetConfigMapNamespace).Get(targetAuthConfigCMName)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not retrieve auth configmap %s/%s to check data before sync: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
	}

	if existingCM != nil && existingCM.Data[authConfigDataKey] == string(authConfigJSON) {
		return nil
	}

	errList := validateAuthenticationConfiguration(*authConfig)
	if len(errList) > 0 {
		return fmt.Errorf("auth config validation failed: %v", errList)
	}

	// update CM
	cm := corev1ac.ConfigMap(targetAuthConfigCMName, targetConfigMapNamespace).
		WithData(map[string]string{authConfigDataKey: string(authConfigJSON)})
	if _, err := c.configMaps.ConfigMaps(targetConfigMapNamespace).Apply(ctx, cm, metav1.ApplyOptions{FieldManager: c.name}); err != nil {
		return fmt.Errorf("could not apply changes to auth configmap %s/%s: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
	}

	syncCtx.Recorder().Eventf(c.eventName, "Synced auth configmap %s/%s", targetConfigMapNamespace, targetAuthConfigCMName)

	return nil
}

// generateAuthConfig creates a structured JWT AuthenticationConfiguration for OIDC
// from the configuration found in the authentication/cluster resource
func (c *externalOIDCController) generateAuthConfig(auth configv1.Authentication) (*apiserverv1beta1.AuthenticationConfiguration, error) {
	authConfig := apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthenticationConfiguration",
			APIVersion: "apiserver.config.k8s.io/v1beta1",
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
			},
		}

		if len(provider.Issuer.Audiences) > 0 {
			jwt.Issuer.Audiences = make([]string, 0, len(provider.Issuer.Audiences))
			for _, aud := range provider.Issuer.Audiences {
				jwt.Issuer.Audiences = append(jwt.Issuer.Audiences, string(aud))
			}
		}

		if len(provider.Issuer.CertificateAuthority.Name) > 0 {
			caConfigMap, err := c.configMapLister.ConfigMaps(caBundleConfigMapNamespace).Get(provider.Issuer.CertificateAuthority.Name)
			if err != nil {
				return nil, fmt.Errorf("could not retrieve auth configmap %s/%s to check CA bundle: %v", caBundleConfigMapNamespace, targetAuthConfigCMName, err)
			}

			caData, ok := caConfigMap.Data["ca-bundle.crt"]
			if !ok || len(caData) == 0 {
				return nil, fmt.Errorf("configmap %s/%s key \"ca-bundle.crt\" missing or empty", caBundleConfigMapNamespace, provider.Issuer.CertificateAuthority.Name)
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
		// validate issuer URL
		var issuerURL *url.URL
		if len(jwt.Issuer.URL) == 0 {
			errs = append(errs, fmt.Errorf("issuer URL must not be empty"))
		} else {
			var err error
			issuerURL, err = url.Parse(jwt.Issuer.URL)
			if err != nil {
				errs = append(errs, err)
			} else {
				if issuerURL.Scheme != "https" {
					errs = append(errs, fmt.Errorf("issuer URL must use HTTPS"))
				}
				if issuerURL.User != nil {
					errs = append(errs, fmt.Errorf("URL must not contain a username or password"))
				}
				if len(issuerURL.RawQuery) > 0 {
					errs = append(errs, fmt.Errorf("URL must not contain a query"))
				}
				if len(issuerURL.Fragment) > 0 {
					errs = append(errs, fmt.Errorf("URL must not contain a fragment"))
				}
			}

			if len(errs) > 0 {
				// if we found URL issues, stop validation to avoid breaking further validations
				return errs
			}
		}

		// validate issuer audiences
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

		// validate issuer CA
		if len(jwt.Issuer.CertificateAuthority) > 0 {
			caCertPool, err := cert.NewPoolFromBytes([]byte(jwt.Issuer.CertificateAuthority))
			if err != nil {
				errs = append(errs, fmt.Errorf("issuer CA is invalid: %v", err))
			}

			if issuerURL != nil {
				if err := validateCACert(*issuerURL, caCertPool); err != nil {
					errs = append(errs, fmt.Errorf("could not validate IDP URL with specified CA cert: %v", err))
				}
			}
		}

		// validate claim validation rules
		seenClaims := sets.NewString()
		for i, rule := range jwt.ClaimValidationRules {
			if len(rule.Claim) == 0 {
				errs = append(errs, fmt.Errorf("claim must not be empty for claim validation rule at index %d", i))
			} else if seenClaims.Has(rule.Claim) {
				errs = append(errs, fmt.Errorf("duplicate claim validation rule: %s", rule.Claim))
			}

			seenClaims.Insert(rule.Claim)
		}

		// validate username claim mapping
		if len(jwt.ClaimMappings.Username.Claim) == 0 {
			errs = append(errs, fmt.Errorf("username claim must not be empty"))
		} else if jwt.ClaimMappings.Username.Prefix == nil {
			errs = append(errs, fmt.Errorf("username prefix must not be nil when claim is set"))
		}

		// validate groups claim mapping
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

	wellKnown := strings.TrimSuffix(hostURL.String(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return fmt.Errorf("could not create well-known HTTP request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET well-known error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected well-known status code %s: %s", resp.Status, body)
	}

	return nil
}
