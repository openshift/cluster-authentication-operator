package operator2

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/openshift/cluster-authentication-operator/pkg/utils"
)

func (c *authOperator) handleServiceCA() (*corev1.ConfigMap, *corev1.Secret, error) {
	cm := c.configMaps.ConfigMaps("openshift-authentication")
	secret := c.secrets.Secrets("openshift-authentication")
	serviceCA, err := cm.Get("v4-0-config-system-service-ca", metav1.GetOptions{})
	if errors.IsNotFound(err) {
		serviceCA, err = cm.Create(defaultServiceCA())
	}
	if err != nil {
		return nil, nil, err
	}

	if len(serviceCA.Data["service-ca.crt"]) == 0 {
		return nil, nil, fmt.Errorf("config map has no service ca data: %#v", serviceCA)
	}

	if err := isValidServiceCA(serviceCA); err != nil {
		// delete the service CA config map so that it is replaced with the proper one in next reconcile loop
		klog.Infof("deleting invalid service CA config map: %#v", serviceCA)
		opts := &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &serviceCA.UID}}
		if err := cm.Delete(serviceCA.Name, opts); err != nil && !errors.IsNotFound(err) {
			klog.Infof("failed to delete invalid service CA config map: %v", err)
		}
		return nil, nil, err
	}

	servingCert, err := secret.Get("v4-0-config-system-serving-cert", metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get serving cert: %v", err)
	}

	return serviceCA, servingCert, nil
}

func isValidServiceCA(ca *corev1.ConfigMap) error {
	if ca.Annotations["service.alpha.openshift.io/inject-cabundle"] != "true" {
		return fmt.Errorf("config map missing injection annotation: %#v", ca)
	}
	return nil
}

func defaultServiceCA() *corev1.ConfigMap {
	meta := utils.DefaultMetaOAuthServerResources()
	meta.Name = "v4-0-config-system-service-ca"
	meta.Annotations["service.alpha.openshift.io/inject-cabundle"] = "true"
	return &corev1.ConfigMap{
		ObjectMeta: meta,
	}
}
