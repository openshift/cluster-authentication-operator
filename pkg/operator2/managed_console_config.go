package operator2

import (
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

func (c *authOperator) handleManagedConfigMap() *corev1.ConfigMap {
	managedConfig, err := c.configMaps.ConfigMaps(managedConfigNamespace).Get(managedConsoleConfig, metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		klog.Infof("error getting managed config: %v", err)
		return nil
	}
	return managedConfig
}
