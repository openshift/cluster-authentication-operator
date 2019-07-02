package operator2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleAPIServerConfig() *configv1.APIServer {
	// technically this should be an observed config loop
	apiServerConfig, err := c.apiserver.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		klog.Infof("error getting API server config: %v", err)
		return &configv1.APIServer{}
	}
	return apiServerConfig
}
