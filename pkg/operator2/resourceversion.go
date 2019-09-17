package operator2

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *authOperator) handleConfigResourceVersions() ([]string, error) {
	var configRVs []string

	configMaps, err := c.configMaps.ConfigMaps("openshift-authentication").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, cm := range configMaps.Items {
		if strings.HasPrefix(cm.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.Name+":"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secrets.Secrets("openshift-authentication").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets.Items {
		if strings.HasPrefix(secret.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.Name+":"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}
