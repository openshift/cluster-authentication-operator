package externaloidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

const (
	targetConfigMapNamespace = "openshift-config"
	targetAuthConfigCMName   = "auth-config"
	authConfigDataKey        = "auth-config.json"
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
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
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
		configMapLister:     kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		configMaps:          configMaps,
	}

	return factory.New().WithInformers(
		// track openshift-config for potential changes to the CA bundle or structured auth config
		kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
		// track auth resource
		configInformer.Config().V1().Authentications().Informer(),
		// track feature gates
		configInformer.Config().V1().FeatureGates().Informer(),
	).ResyncEvery(wait.Jitter(time.Minute, 1.0)).
		WithSync(c.sync).
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

	switch auth.Spec.Type {
	case configv1.AuthenticationTypeIntegratedOAuth, configv1.AuthenticationTypeNone, "":
		if _, err := c.configMapLister.ConfigMaps(targetConfigMapNamespace).Get(targetAuthConfigCMName); errors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return fmt.Errorf("could not retrieve auth configmap %s/%s before attempting to delete: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
		}

		// OIDC auth-config configmap exists; delete it
		if err := c.configMaps.ConfigMaps(targetConfigMapNamespace).Delete(ctx, targetAuthConfigCMName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("could not delete existing configmap %s/%s: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
		} else if err == nil {
			syncCtx.Recorder().Eventf(c.eventName, "Removed auth configmap %s/%s", targetConfigMapNamespace, targetAuthConfigCMName)
		}
		return nil

	case configv1.AuthenticationTypeOIDC:
		authConfig, err := c.generateAuthConfig(*auth)
		if err != nil {
			return err
		}

		if synced, err := c.syncAuthConfig(ctx, *authConfig); err != nil {
			return err
		} else if synced {
			syncCtx.Recorder().Eventf(c.eventName, "Synced auth configmap %s/%s", targetConfigMapNamespace, targetAuthConfigCMName)
		}

		return nil
	}

	// this should never happen; resource is CEL-validated
	return fmt.Errorf("invalid auth type: %s", auth.Spec.Type)
}

// generateAuthConfig creates a structured JWT AuthenticationConfiguration for OIDC
// from the configuration found in the authentication/cluster resource
func (c *externalOIDCController) generateAuthConfig(auth configv1.Authentication) (*apiserver.AuthenticationConfiguration, error) {
	authConfig := apiserver.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthenticationConfiguration",
			APIVersion: "apiserver.config.k8s.io",
		},
	}

	if len(auth.Spec.OIDCProviders) == 0 {
		return nil, fmt.Errorf("no OIDC providers configured")
	}

	if len(auth.Spec.OIDCProviders) > 1 {
		return nil, fmt.Errorf("multiple OIDC providers not supported")
	}

	for _, provider := range auth.Spec.OIDCProviders {
		jwt := apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{
				URL:                 provider.Issuer.URL,
				AudienceMatchPolicy: apiserver.AudienceMatchPolicyMatchAny,
			},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{
					Claim: provider.ClaimMappings.Username.Claim,
				},
				Groups: apiserver.PrefixedClaimOrExpression{
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
			caConfigMap, err := c.configMapLister.ConfigMaps(targetConfigMapNamespace).Get(provider.Issuer.CertificateAuthority.Name)
			if err != nil {
				return nil, fmt.Errorf("could not retrieve auth configmap %s/%s to check CA bundle: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
			}

			caData, ok := caConfigMap.Data["ca-bundle.crt"]
			if !ok || len(caData) == 0 {
				return nil, fmt.Errorf("configmap %s/%s key \"ca-bundle.crt\" missing or empty", targetConfigMapNamespace, provider.Issuer.CertificateAuthority.Name)
			}

			jwt.Issuer.CertificateAuthority = caData
		}

		var prefix string
		switch provider.ClaimMappings.Username.PrefixPolicy {
		case configv1.NoOpinion:
			prefix = ""
		case configv1.NoPrefix:
			prefix = "-"
		case configv1.Prefix:
			if provider.ClaimMappings.Username.Prefix == nil {
				return nil, fmt.Errorf("nil username prefix while policy expects one")
			} else {
				prefix = provider.ClaimMappings.Username.Prefix.PrefixString
			}
		}
		jwt.ClaimMappings.Username.Prefix = &prefix

		for i, rule := range provider.ClaimValidationRules {
			if rule.Type != configv1.TokenValidationRuleTypeRequiredClaim {
				return nil, fmt.Errorf("invalid claim validation rule type: %s", rule.Type)
			}

			if rule.RequiredClaim == nil {
				return nil, fmt.Errorf("empty validation rule at index %d", i)
			}

			jwt.ClaimValidationRules = append(jwt.ClaimValidationRules, apiserver.ClaimValidationRule{
				Claim:         rule.RequiredClaim.Claim,
				RequiredValue: rule.RequiredClaim.RequiredValue,
			})
		}

		authConfig.JWT = append(authConfig.JWT, jwt)
	}

	// do the same validation that kube-apiserver does on the auth config to catch any errors early
	errList := validation.ValidateAuthenticationConfiguration(&authConfig, nil)
	if len(errList) > 0 {
		return nil, fmt.Errorf("auth config validation failed: %v", errList.ToAggregate())
	}

	return &authConfig, nil
}

// syncAuthConfig serializes the structured auth config into a configmap
// and syncs it to the target namespace if it has changed
func (c *externalOIDCController) syncAuthConfig(ctx context.Context, authConfig apiserver.AuthenticationConfiguration) (synced bool, err error) {
	authConfigJSON, err := json.Marshal(authConfig)
	if err != nil {
		return false, fmt.Errorf("could not marshal auth config into JSON: %v", err)
	}

	existingCM, err := c.configMapLister.ConfigMaps(targetConfigMapNamespace).Get(targetAuthConfigCMName)
	if err != nil && !errors.IsNotFound(err) {
		return false, fmt.Errorf("could not retrieve auth configmap %s/%s to check data before sync: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
	}

	if existingCM != nil && existingCM.Data[authConfigDataKey] == string(authConfigJSON) {
		return false, nil
	}

	// update CM
	cm := corev1ac.ConfigMap(targetAuthConfigCMName, targetConfigMapNamespace).
		WithData(map[string]string{authConfigDataKey: string(authConfigJSON)})
	if _, err := c.configMaps.ConfigMaps(targetConfigMapNamespace).Apply(ctx, cm, metav1.ApplyOptions{FieldManager: c.name}); err != nil {
		return false, fmt.Errorf("could not apply changes to auth configmap %s/%s: %v", targetConfigMapNamespace, targetAuthConfigCMName, err)
	}

	return true, nil
}
