package operator2

import (
	"net/url"
	"regexp"

	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleConsoleConfig() *configv1.Console {
	// technically this should be an observed config loop
	consoleConfig, err := c.console.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		// FIXME: fix when the console team starts using this
		return &configv1.Console{}
	}
	return consoleConfig
}

func consoleToDeploymentData(console *configv1.Console) (string, []string) {
	host := console.Status.PublicHostname

	if len(host) == 0 {
		return "", nil
	}

	assetPublicURL := "https://" + host  // needs to be a valid URL
	corsAllowedOrigins := []string{host} // needs to be valid regexps

	if _, err := url.Parse(assetPublicURL); err != nil { // should never happen
		glog.Errorf("failed to parse assetPublicURL %s: %v", assetPublicURL, err)
		return "", nil
	}
	for _, corsAllowedOrigin := range corsAllowedOrigins {
		if _, err := regexp.Compile(corsAllowedOrigin); err != nil { // also should never happen
			glog.Errorf("failed to parse corsAllowedOrigin %s: %v", corsAllowedOrigin, err)
			return "", nil
		}
	}

	return assetPublicURL, corsAllowedOrigins
}
