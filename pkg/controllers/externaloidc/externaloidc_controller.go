package externaloidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/operators"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"golang.org/x/net/http/httpproxy"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
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

// oidcGenerationState holds compilation results gathered during JWT generation
// that are needed for cross-field validation (e.g. email_verified enforcement).
type oidcGenerationState struct {
	usernameResult         *authenticationcel.CompilationResult
	extraResults           []authenticationcel.CompilationResult
	claimValidationResults []authenticationcel.CompilationResult
}

type externalOIDCController struct {
	name            string
	eventName       string
	authLister      configv1listers.AuthenticationLister
	configMapLister corev1listers.ConfigMapLister
	configMaps      corev1client.ConfigMapsGetter
	featureGates    featuregates.FeatureGate
}

func NewExternalOIDCController(
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	configInformer configinformers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	configMaps corev1client.ConfigMapsGetter,
	recorder events.Recorder,
	featureGates featuregates.FeatureGate,
) factory.Controller {
	c := &externalOIDCController{
		name:      "ExternalOIDCController",
		eventName: "external-oidc-controller",

		authLister:      configInformer.Config().V1().Authentications().Lister(),
		configMapLister: kubeInformersForNamespaces.ConfigMapLister(),
		configMaps:      configMaps,
		featureGates:    featureGates,
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
	if _, err := c.configMapLister.ConfigMaps(managedNamespace).Get(targetAuthConfigCMName); apierrors.IsNotFound(err) {
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

	errs := []error{}
	for _, provider := range auth.Spec.OIDCProviders {
		jwt, err := generateJWTForProvider(provider, c.configMapLister, c.featureGates, auth.Spec.ServiceAccountIssuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		authConfig.JWT = append(authConfig.JWT, jwt)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &authConfig, nil
}

func generateJWTForProvider(provider configv1.OIDCProvider, configMapLister corev1listers.ConfigMapLister, featureGates featuregates.FeatureGate, serviceAccountIssuer string) (apiserverv1beta1.JWTAuthenticator, error) {
	out := apiserverv1beta1.JWTAuthenticator{}

	issuer, err := generateIssuer(provider.Issuer, configMapLister, serviceAccountIssuer)
	if err != nil {
		return apiserverv1beta1.JWTAuthenticator{}, fmt.Errorf("generating issuer for provider %q: %v", provider.Name, err)
	}

	state := &oidcGenerationState{}

	claimMappings, err := generateClaimMappings(provider.ClaimMappings, issuer.URL, featureGates, state)
	if err != nil {
		return apiserverv1beta1.JWTAuthenticator{}, fmt.Errorf("generating claimMappings for provider %q: %v", provider.Name, err)
	}

	claimValidationRules, err := generateClaimValidationRules(state, provider.ClaimValidationRules...)
	if err != nil {
		return apiserverv1beta1.JWTAuthenticator{}, fmt.Errorf("generating claimValidationRules for provider %q: %v", provider.Name, err)
	}

	if featureGates.Enabled(features.FeatureGateExternalOIDCWithUpstreamParity) {
		if err := validateEmailVerifiedUsage(
			state.usernameResult,
			state.extraResults,
			state.claimValidationResults,
		); err != nil {
			return apiserverv1beta1.JWTAuthenticator{}, fmt.Errorf("validating email claim usage for provider %q: %v", provider.Name, err)
		}
		var userValidationRules []apiserverv1beta1.UserValidationRule
		userValidationRules, err = generateUserValidationRules(provider.UserValidationRules)
		if err != nil {
			return apiserverv1beta1.JWTAuthenticator{}, fmt.Errorf("generating userValidationRules for provider %q: %v", provider.Name, err)
		}
		out.UserValidationRules = userValidationRules
	}
	out.Issuer = issuer
	out.ClaimMappings = claimMappings
	out.ClaimValidationRules = claimValidationRules

	return out, nil
}

func generateIssuer(issuer configv1.TokenIssuer, configMapLister corev1listers.ConfigMapLister, serviceAccountIssuer string) (apiserverv1beta1.Issuer, error) {
	out := apiserverv1beta1.Issuer{}

	if len(serviceAccountIssuer) > 0 {
		if issuer.URL == serviceAccountIssuer {
			return apiserverv1beta1.Issuer{}, errors.New("issuer url cannot overlap with the ServiceAccount issuer url")
		}
	}

	out.URL = issuer.URL
	out.AudienceMatchPolicy = apiserverv1beta1.AudienceMatchPolicyMatchAny

	for _, audience := range issuer.Audiences {
		out.Audiences = append(out.Audiences, string(audience))
	}
	if len(issuer.DiscoveryURL) > 0 {
		// Validate the URL scheme
		u, err := url.Parse(issuer.DiscoveryURL)
		if err != nil {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("invalid discovery URL: %v", err)
		}
		if strings.TrimRight(issuer.DiscoveryURL, "/") == strings.TrimRight(issuer.URL, "/") {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must not be identical to issuer URL")
		}
		if u.Scheme != "https" {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must use https, got %q", u.Scheme)
		}
		if u.Host == "" {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must include a host")
		}
		if u.User != nil {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must not contain user info")
		}
		if len(u.RawQuery) > 0 {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must not contain a query string")
		}
		if len(u.Fragment) > 0 {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("discovery URL must not contain a fragment")
		}
		out.DiscoveryURL = &issuer.DiscoveryURL
	}
	if len(issuer.CertificateAuthority.Name) > 0 {
		ca, err := getCertificateAuthorityFromConfigMap(issuer.CertificateAuthority.Name, configMapLister)
		if err != nil {
			return apiserverv1beta1.Issuer{}, fmt.Errorf("getting CertificateAuthority for issuer: %v", err)
		}
		out.CertificateAuthority = ca
	}

	return out, nil
}

func getCertificateAuthorityFromConfigMap(name string, configMapLister corev1listers.ConfigMapLister) (string, error) {
	caConfigMap, err := configMapLister.ConfigMaps(configNamespace).Get(name)
	if err != nil {
		return "", fmt.Errorf("could not retrieve auth configmap %s/%s to check CA bundle: %v", configNamespace, name, err)
	}

	caData, ok := caConfigMap.Data["ca-bundle.crt"]
	if !ok || len(caData) == 0 {
		return "", fmt.Errorf("configmap %s/%s key \"ca-bundle.crt\" missing or empty", configNamespace, name)
	}

	return caData, nil
}

func generateClaimMappings(claimMappings configv1.TokenClaimMappings, issuerURL string, featureGates featuregates.FeatureGate, state *oidcGenerationState) (apiserverv1beta1.ClaimMappings, error) {
	out := apiserverv1beta1.ClaimMappings{}

	username, usernameResult, err := generateUsernameClaimMapping(claimMappings.Username, issuerURL, featureGates)
	if err != nil {
		return apiserverv1beta1.ClaimMappings{}, fmt.Errorf("generating username claim mapping: %v", err)
	}
	state.usernameResult = usernameResult

	groups, err := generateGroupsClaimMapping(claimMappings.Groups, featureGates)
	if err != nil {
		return apiserverv1beta1.ClaimMappings{}, fmt.Errorf("generating group claim mapping: %v", err)
	}
	out.Username = username
	out.Groups = groups

	if featureGates.Enabled(features.FeatureGateExternalOIDCWithAdditionalClaimMappings) {
		uid, err := generateUIDClaimMapping(claimMappings.UID)
		if err != nil {
			return apiserverv1beta1.ClaimMappings{}, fmt.Errorf("generating uid claim mapping: %v", err)
		}

		extras, extraResults, err := generateExtraClaimMapping(claimMappings.Extra...)
		if err != nil {
			return apiserverv1beta1.ClaimMappings{}, fmt.Errorf("generating extra claim mapping: %v", err)
		}

		out.UID = uid
		out.Extra = extras
		state.extraResults = extraResults
	}

	return out, nil
}

func generateUsernameClaimMapping(usernameClaimMapping configv1.UsernameClaimMapping, issuerURL string, featureGates featuregates.FeatureGate) (apiserverv1beta1.PrefixedClaimOrExpression, *authenticationcel.CompilationResult, error) {
	if featureGates.Enabled(features.FeatureGateExternalOIDCWithUpstreamParity) {
		return generateUsernameClaimMappingWithParity(usernameClaimMapping, issuerURL)
	}
	return generateUsernameClaimMappingLegacy(usernameClaimMapping, issuerURL)
}

func generateUsernameClaimMappingWithParity(usernameClaimMapping configv1.UsernameClaimMapping, issuerURL string) (apiserverv1beta1.PrefixedClaimOrExpression, *authenticationcel.CompilationResult, error) {
	out := apiserverv1beta1.PrefixedClaimOrExpression{}

	if len(usernameClaimMapping.Expression) == 0 && len(usernameClaimMapping.Claim) == 0 {
		return out, nil, fmt.Errorf("username claim mapping is required and either claim or expression must be set")
	}

	if len(usernameClaimMapping.Expression) > 0 && len(usernameClaimMapping.Claim) > 0 {
		return out, nil, fmt.Errorf("username claim mapping must not set both claim and expression")
	}

	if len(usernameClaimMapping.Expression) > 0 && usernameClaimMapping.PrefixPolicy == configv1.Prefix {
		return out, nil, fmt.Errorf("username claim mappings cannot have a prefix set when using an expression based mapping. If you want to set a prefix while using an expression mapping, set the prefix in the expression")
	}

	if len(usernameClaimMapping.Expression) > 0 {
		result, err := validateCELExpression(&authenticationcel.ClaimMappingExpression{
			Expression: usernameClaimMapping.Expression,
		})
		if err != nil {
			return out, nil, fmt.Errorf("invalid CEL expression: %v", err)
		}
		out.Expression = usernameClaimMapping.Expression
		return out, &result, nil
	}

	if len(usernameClaimMapping.Claim) > 0 {
		out.Claim = usernameClaimMapping.Claim

		// prefix can only be set when using a direct claim name, so only attempt to set it
		// if we are certain we are using a direct claim reference and not an expression
		switch usernameClaimMapping.PrefixPolicy {
		case configv1.Prefix:
			if usernameClaimMapping.Prefix == nil {
				return out, nil, fmt.Errorf("nil username prefix while policy expects one")
			}
			out.Prefix = &usernameClaimMapping.Prefix.PrefixString
		case configv1.NoPrefix:
			out.Prefix = ptr.To("")
		case configv1.NoOpinion:
			prefix := ""
			if usernameClaimMapping.Claim != "email" {
				prefix = issuerURL + "#"
			}
			out.Prefix = &prefix
		default:
			return out, nil, fmt.Errorf("invalid username prefix policy: %s", usernameClaimMapping.PrefixPolicy)
		}
	}

	return out, nil, nil
}

func generateUsernameClaimMappingLegacy(usernameClaimMapping configv1.UsernameClaimMapping, issuerURL string) (apiserverv1beta1.PrefixedClaimOrExpression, *authenticationcel.CompilationResult, error) {
	out := apiserverv1beta1.PrefixedClaimOrExpression{}

	if len(usernameClaimMapping.Claim) == 0 {
		return out, nil, fmt.Errorf("username claim is required but an empty value was provided")
	}
	out.Claim = usernameClaimMapping.Claim

	switch usernameClaimMapping.PrefixPolicy {
	case configv1.Prefix:
		if usernameClaimMapping.Prefix == nil {
			return out, nil, fmt.Errorf("nil username prefix while policy expects one")
		}
		out.Prefix = &usernameClaimMapping.Prefix.PrefixString
	case configv1.NoPrefix:
		out.Prefix = ptr.To("")
	case configv1.NoOpinion:
		prefix := ""
		if usernameClaimMapping.Claim != "email" {
			prefix = issuerURL + "#"
		}
		out.Prefix = &prefix
	default:
		return out, nil, fmt.Errorf("invalid username prefix policy: %s", usernameClaimMapping.PrefixPolicy)
	}

	return out, nil, nil
}

func generateGroupsClaimMapping(groupsMapping configv1.PrefixedClaimMapping, featureGates featuregates.FeatureGate) (apiserverv1beta1.PrefixedClaimOrExpression, error) {
	out := apiserverv1beta1.PrefixedClaimOrExpression{}
	if featureGates.Enabled(features.FeatureGateExternalOIDCWithUpstreamParity) {
		if len(groupsMapping.Expression) > 0 && len(groupsMapping.Claim) > 0 {
			return out, fmt.Errorf("groups claim mapping must not set both claim and expression")
		}
		if len(groupsMapping.Expression) > 0 && len(groupsMapping.Prefix) > 0 {
			return apiserverv1beta1.PrefixedClaimOrExpression{}, fmt.Errorf("groups claim mapping must not set prefix when expression is set")
		}

		if len(groupsMapping.Expression) > 0 {
			if _, err := validateCELExpression(&authenticationcel.ClaimMappingExpression{
				Expression: groupsMapping.Expression,
			}); err != nil {
				return apiserverv1beta1.PrefixedClaimOrExpression{}, fmt.Errorf("invalid CEL expression: %v", err)
			}
			out.Expression = groupsMapping.Expression
			return out, nil
		}
	}

	out.Claim = groupsMapping.Claim
	out.Prefix = &groupsMapping.Prefix

	return out, nil
}

func generateUIDClaimMapping(uid *configv1.TokenClaimOrExpressionMapping) (apiserverv1beta1.ClaimOrExpression, error) {
	out := apiserverv1beta1.ClaimOrExpression{}

	// UID mapping can only specify either claim or expression, not both.
	// This should be rejected at admission time of the authentications.config.openshift.io CRD.
	// Even though this is the case, we still perform a runtime validation to ensure we never
	// attempt to create an invalid configuration.
	// If neither claim or expression is specified, default the claim to "sub"
	switch {
	case uid == nil:
		out.Claim = "sub"
	case len(uid.Claim) > 0 && len(uid.Expression) == 0:
		out.Claim = uid.Claim
	case len(uid.Expression) > 0 && len(uid.Claim) == 0:
		if _, err := validateCELExpression(&authenticationcel.ClaimMappingExpression{
			Expression: uid.Expression,
		}); err != nil {
			return apiserverv1beta1.ClaimOrExpression{}, fmt.Errorf("validating expression: %v", err)
		}
		out.Expression = uid.Expression
	case len(uid.Claim) > 0 && len(uid.Expression) > 0:
		return apiserverv1beta1.ClaimOrExpression{}, fmt.Errorf("uid mapping must set either claim or expression, not both: %v", uid)
	default:
		return apiserverv1beta1.ClaimOrExpression{}, fmt.Errorf("unable to handle uid mapping: %v", uid)
	}

	return out, nil
}

func generateExtraClaimMapping(extraMappings ...configv1.ExtraMapping) ([]apiserverv1beta1.ExtraMapping, []authenticationcel.CompilationResult, error) {
	out := []apiserverv1beta1.ExtraMapping{}
	var compilationResults []authenticationcel.CompilationResult
	errs := []error{}
	for _, extraMapping := range extraMappings {
		extra, result, err := generateExtraMapping(extraMapping)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, extra)
		if result != nil {
			compilationResults = append(compilationResults, *result)
		}
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return out, compilationResults, nil
}

func generateExtraMapping(extraMapping configv1.ExtraMapping) (apiserverv1beta1.ExtraMapping, *authenticationcel.CompilationResult, error) {
	out := apiserverv1beta1.ExtraMapping{}

	if len(extraMapping.Key) == 0 {
		return apiserverv1beta1.ExtraMapping{}, nil, fmt.Errorf("extra mapping must set a key, but none was provided: %v", extraMapping)
	}

	if len(extraMapping.ValueExpression) == 0 {
		return apiserverv1beta1.ExtraMapping{}, nil, fmt.Errorf("extra mapping must set a valueExpression, but none was provided: %v", extraMapping)
	}

	result, err := validateCELExpression(&authenticationcel.ExtraMappingExpression{
		Key:        extraMapping.Key,
		Expression: extraMapping.ValueExpression,
	})
	if err != nil {
		return apiserverv1beta1.ExtraMapping{}, nil, fmt.Errorf("validating expression: %v", err)
	}

	out.Key = extraMapping.Key
	out.ValueExpression = extraMapping.ValueExpression

	return out, &result, nil
}

func generateClaimValidationRules(state *oidcGenerationState, claimValidationRules ...configv1.TokenClaimValidationRule) ([]apiserverv1beta1.ClaimValidationRule, error) {
	out := []apiserverv1beta1.ClaimValidationRule{}
	errs := []error{}
	for _, claimValidationRule := range claimValidationRules {
		rule, result, err := generateClaimValidationRule(claimValidationRule)
		if err != nil {
			errs = append(errs, fmt.Errorf("generating claimValidationRule: %v", err))
			continue
		}
		out = append(out, rule)
		if result != nil {
			state.claimValidationResults = append(state.claimValidationResults, *result)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func generateClaimValidationRule(claimValidationRule configv1.TokenClaimValidationRule) (apiserverv1beta1.ClaimValidationRule, *authenticationcel.CompilationResult, error) {
	out := apiserverv1beta1.ClaimValidationRule{}
	switch claimValidationRule.Type {
	case configv1.TokenValidationRuleTypeRequiredClaim:
		if claimValidationRule.RequiredClaim == nil {
			return apiserverv1beta1.ClaimValidationRule{}, nil, fmt.Errorf("claimValidationRule.type is %s and requiredClaim is not set", configv1.TokenValidationRuleTypeRequiredClaim)
		}
		out.Claim = claimValidationRule.RequiredClaim.Claim
		out.RequiredValue = claimValidationRule.RequiredClaim.RequiredValue
	case configv1.TokenValidationRuleTypeCEL:
		if len(claimValidationRule.CEL.Expression) == 0 {
			return apiserverv1beta1.ClaimValidationRule{}, nil, fmt.Errorf("claimValidationRule.type is %s and expression is not set", configv1.TokenValidationRuleTypeCEL)
		}
		result, err := validateCELExpression(&authenticationcel.ClaimValidationCondition{
			Expression: claimValidationRule.CEL.Expression,
		})
		if err != nil {
			return apiserverv1beta1.ClaimValidationRule{}, nil, fmt.Errorf("invalid CEL expression: %v", err)
		}
		out.Expression = claimValidationRule.CEL.Expression
		out.Message = claimValidationRule.CEL.Message
		return out, &result, nil
	default:
		return apiserverv1beta1.ClaimValidationRule{}, nil, fmt.Errorf("unknown claimValidationRule type %q", claimValidationRule.Type)
	}
	return out, nil, nil
}
func generateUserValidationRule(rule configv1.TokenUserValidationRule) (apiserverv1beta1.UserValidationRule, error) {
	if len(rule.Expression) == 0 {
		return apiserverv1beta1.UserValidationRule{}, fmt.Errorf("userValidationRule expression must be non-empty")
	}

	// validate CEL expression
	if _, err := validateUserCELExpression(&authenticationcel.UserValidationCondition{
		Expression: rule.Expression,
	}); err != nil {
		return apiserverv1beta1.UserValidationRule{}, fmt.Errorf("invalid CEL expression: %v", err)
	}

	return apiserverv1beta1.UserValidationRule{
		Expression: rule.Expression,
		Message:    rule.Message,
	}, nil
}

func generateUserValidationRules(rules []configv1.TokenUserValidationRule) ([]apiserverv1beta1.UserValidationRule, error) {
	out := []apiserverv1beta1.UserValidationRule{}
	errs := []error{}

	for _, r := range rules {
		uvr, err := generateUserValidationRule(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("generating userValidationRule: %v", err))
			continue
		}
		out = append(out, uvr)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return out, nil
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

// validateCELExpression validates a CEL expression using the provided expression accessor.
// It uses the default authentication CEL compiler that the KAS uses and thus defaults to
// validating CEL expressions based on the version of the k8s dependencies used by the
// cluster-authentication-operator.
func validateCELExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error) {
	return authenticationcel.NewDefaultCompiler().CompileClaimsExpression(expressionAccessor)
}

// validateUserCELExpression validates a user CEL expression using the user.* scope.
func validateUserCELExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error) {
	return authenticationcel.NewDefaultCompiler().CompileUserExpression(expressionAccessor)
}

// validateEmailVerifiedUsage enforces that when claims.email is used in the
// username expression, claims.email_verified must be referenced in at least
// one of: username.expression, extra[*].valueExpression, or
// claimValidationRules[*].cel.expression.
// This mirrors the upstream KAS validation logic.
func validateEmailVerifiedUsage(
	usernameResult *authenticationcel.CompilationResult,
	extraResults []authenticationcel.CompilationResult,
	claimValidationResults []authenticationcel.CompilationResult,
) error {
	if usernameResult == nil {
		return nil
	}

	if !usesEmailClaim(usernameResult.AST) {
		return nil
	}

	if usesEmailVerifiedClaim(usernameResult.AST) || anyUsesEmailVerifiedClaim(extraResults) || anyUsesEmailVerifiedClaim(claimValidationResults) {
		return nil
	}

	return fmt.Errorf("claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression")
}

// usesEmailClaim, usesEmailVerifiedClaim, anyUsesEmailVerifiedClaim, hasSelectExp,
// isIdentOperand, and isConstField are copied from the upstream Kubernetes apiserver
// CEL validation logic introduced in https://github.com/kubernetes/kubernetes/pull/123737 (commit 121607e):
// https://github.com/kubernetes/kubernetes/blob/bfb362c57578518bed8e08a56a7318bab9b57429/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go#L443
func usesEmailClaim(ast *celgo.Ast) bool {
	if ast == nil {
		return false
	}
	return hasSelectExp(ast.Expr(), "claims", "email")
}

func usesEmailVerifiedClaim(ast *celgo.Ast) bool {
	if ast == nil {
		return false
	}
	return hasSelectExp(ast.Expr(), "claims", "email_verified")
}

func anyUsesEmailVerifiedClaim(results []authenticationcel.CompilationResult) bool {
	for _, result := range results {
		if usesEmailVerifiedClaim(result.AST) {
			return true
		}
	}
	return false
}

func hasSelectExp(exp *exprpb.Expr, operand, field string) bool {
	if exp == nil {
		return false
	}
	switch e := exp.ExprKind.(type) {
	case *exprpb.Expr_ConstExpr,
		*exprpb.Expr_IdentExpr:
		return false
	case *exprpb.Expr_SelectExpr:
		s := e.SelectExpr
		if s == nil {
			return false
		}
		if isIdentOperand(s.Operand, operand) && s.Field == field {
			return true
		}
		return hasSelectExp(s.Operand, operand, field)
	case *exprpb.Expr_CallExpr:
		c := e.CallExpr
		if c == nil {
			return false
		}
		if c.Target == nil && c.Function == operators.OptSelect && len(c.Args) == 2 &&
			isIdentOperand(c.Args[0], operand) && isConstField(c.Args[1], field) {
			return true
		}
		for _, arg := range c.Args {
			if hasSelectExp(arg, operand, field) {
				return true
			}
		}
		return hasSelectExp(c.Target, operand, field)
	case *exprpb.Expr_ListExpr:
		l := e.ListExpr
		if l == nil {
			return false
		}
		for _, element := range l.Elements {
			if hasSelectExp(element, operand, field) {
				return true
			}
		}
		return false
	case *exprpb.Expr_StructExpr:
		s := e.StructExpr
		if s == nil {
			return false
		}
		for _, entry := range s.Entries {
			if hasSelectExp(entry.GetMapKey(), operand, field) {
				return true
			}
			if hasSelectExp(entry.Value, operand, field) {
				return true
			}
		}
		return false
	case *exprpb.Expr_ComprehensionExpr:
		c := e.ComprehensionExpr
		if c == nil {
			return false
		}
		return hasSelectExp(c.IterRange, operand, field) ||
			hasSelectExp(c.AccuInit, operand, field) ||
			hasSelectExp(c.LoopCondition, operand, field) ||
			hasSelectExp(c.LoopStep, operand, field) ||
			hasSelectExp(c.Result, operand, field)
	default:
		return false
	}
}

func isIdentOperand(exp *exprpb.Expr, operand string) bool {
	if len(operand) == 0 {
		return false
	}
	id := exp.GetIdentExpr()
	return id != nil && id.Name == operand
}

func isConstField(exp *exprpb.Expr, field string) bool {
	if len(field) == 0 {
		return false
	}
	c := exp.GetConstExpr()
	return c != nil && c.GetStringValue() == field
}
