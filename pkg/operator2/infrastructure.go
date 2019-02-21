package operator2

import (
	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleInfrastructureConfig() *configv1.Infrastructure {
	infrastructureConfig, err := c.infrastructure.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		glog.Infof("error getting infrastructure config: %v", err)
		// have a placeholder that will at least look reasonable in the token request endpoint
		return &configv1.Infrastructure{Status: configv1.InfrastructureStatus{APIServerURL: "<api_server_url>"}}
	}
	return infrastructureConfig
}
