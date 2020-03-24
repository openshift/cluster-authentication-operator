package operator2

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v2"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
)

const (
	ocpBrand = "ocp"
	okdBrand = "okd"
)

func (c *authOperator) handleBrandingTemplates(ctx context.Context, configTemplates configv1.OAuthTemplates, syncData configSyncData) (*osinv1.OAuthTemplates, error) {
	templates := osinv1.OAuthTemplates{}

	brand, err := c.getConsoleBranding(ctx)
	if err != nil {
		return nil, err
	}

	switch brand {
	case okdBrand:
		// do nothing, OAuth server has right branding for this

	case ocpBrand, "dedicated", "online", "azure":
		// all of these are equivalent to ocp
		templates = osinv1.OAuthTemplates{
			Login:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/login.html",
			ProviderSelection: "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/providers.html",
			Error:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/errors.html",
		}

	default:
		if defaultBrand == ocpBrand {
			// build-time ocp selection
			templates = osinv1.OAuthTemplates{
				Login:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/login.html",
				ProviderSelection: "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/providers.html",
				Error:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/errors.html",
			}
		}
	}

	// user-configured overrides everything else, individually.
	if hasSecretRef(configTemplates.Login) {
		templates.Login = syncData.addTemplateSecret(configTemplates.Login, "login", configv1.LoginTemplateKey)
	}
	if hasSecretRef(configTemplates.ProviderSelection) {
		templates.ProviderSelection = syncData.addTemplateSecret(configTemplates.ProviderSelection, "provider-selection", configv1.ProviderSelectionTemplateKey)
	}
	if hasSecretRef(configTemplates.Error) {
		templates.Error = syncData.addTemplateSecret(configTemplates.Error, "error", configv1.ErrorsTemplateKey)
	}

	empty := osinv1.OAuthTemplates{}
	if templates == empty {
		return nil, nil
	}

	return &templates, nil
}

func (c *authOperator) getConsoleBranding(ctx context.Context) (string, error) {
	cm, err := c.configMaps.ConfigMaps("openshift-authentication").Get(ctx, "v4-0-config-system-console-config", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("error getting console-config: %v", err)
	}

	data := cm.Data["console-config.yaml"]
	if len(data) == 0 {
		return "", nil
	}

	config := &ConsoleConfig{}
	if err := yaml.Unmarshal([]byte(data), config); err != nil {
		return "", fmt.Errorf("error parsing console-config: %v", err)
	}

	return config.Branding, nil
}

func hasSecretRef(ref configv1.SecretNameReference) bool {
	return len(ref.Name) > 0
}
