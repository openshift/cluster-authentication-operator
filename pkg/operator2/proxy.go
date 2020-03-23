package operator2

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleProxyConfig(ctx context.Context) *configv1.Proxy {
	proxyConfig, err := c.proxy.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		klog.Infof("error getting proxy config: %v", err)
		return &configv1.Proxy{}
	}
	return proxyConfig
}
