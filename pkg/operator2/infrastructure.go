package operator2

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleInfrastructureConfig(ctx context.Context) *configv1.Infrastructure {
	infrastructureConfig, err := c.infrastructure.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		klog.Infof("error getting infrastructure config: %v", err)
		// have a placeholder that will at least look reasonable in the token request endpoint
		return &configv1.Infrastructure{Status: configv1.InfrastructureStatus{APIServerURL: "<api_server_url>"}}
	}
	return infrastructureConfig
}
