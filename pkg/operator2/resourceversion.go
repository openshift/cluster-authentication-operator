package operator2

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *authOperator) handleConfigResourceVersions() ([]string, error) {
	var configRVs []string

	configMaps, err := c.configMaps.ConfigMaps(targetNamespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, cm := range configMaps.Items {
		if strings.HasPrefix(cm.Name, configVersionPrefix) {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secrets.Secrets(targetNamespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets.Items {
		if strings.HasPrefix(secret.Name, configVersionPrefix) {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}
