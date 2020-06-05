package oauth

import (
	"fmt"

	"gopkg.in/yaml.v2"

	"k8s.io/apimachinery/pkg/api/errors"
	corelistersv1 "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
)

const (
	ocpBrand = "ocp"
	okdBrand = "okd"
)

// ----- partial copy of console CLI config -----

type ConsoleConfig struct {
	Customization `yaml:"customization"`
}

type Customization struct {
	Branding string `yaml:"branding"`
}

// ----- end of copy -----

func convertTemplatesWithBranding(cmLister corelistersv1.ConfigMapLister, configTemplates *configv1.OAuthTemplates) (*osinv1.OAuthTemplates, map[string]string, error) {
	templates := osinv1.OAuthTemplates{}
	templateSyncData := map[string]string{}

	ocpDefaults := osinv1.OAuthTemplates{
		Login:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/login.html",
		ProviderSelection: "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/providers.html",
		Error:             "/var/config/system/secrets/v4-0-config-system-ocp-branding-template/errors.html",
	}

	brand, err := getConsoleBranding(cmLister)
	if err != nil {
		return nil, nil, err
	}

	switch brand {
	case okdBrand:
		// do nothing, OAuth server has right branding for this

	case ocpBrand, "dedicated", "online", "azure":
		// all of these are equivalent to ocp
		templates = ocpDefaults

	default:
		if defaultBrand == ocpBrand {
			// build-time ocp selection
			templates = ocpDefaults
		}
	}

	// user-configured overrides
	if len(configTemplates.Login.Name) > 0 {
		templateSyncData[configv1.LoginTemplateKey] = configTemplates.Login.Name
		templates.Login = "/var/config/user/template/secret/v4-0-config-user-template-login/login.html"
	}
	if len(configTemplates.ProviderSelection.Name) > 0 {
		templateSyncData[configv1.ProviderSelectionTemplateKey] = configTemplates.ProviderSelection.Name
		templates.ProviderSelection = "/var/config/user/template/secret/v4-0-config-user-template-provider-selection/providers.html"
	}
	if len(configTemplates.Error.Name) > 0 {
		templateSyncData[configv1.ErrorsTemplateKey] = configTemplates.Error.Name
		templates.Error = "/var/config/user/template/secret/v4-0-config-user-template-error/errors.html"
	}

	empty := osinv1.OAuthTemplates{}
	if templates == empty {
		return nil, nil, nil
	}

	return &templates, templateSyncData, nil
}

func getConsoleBranding(cmLister corelistersv1.ConfigMapLister) (string, error) {
	cm, err := cmLister.ConfigMaps("openshift-authentication").Get("v4-0-config-system-console-config")
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
