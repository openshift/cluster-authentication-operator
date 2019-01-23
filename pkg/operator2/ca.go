package operator2

import (
	"fmt"

	"github.com/golang/glog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	injectCABundleAnnotationName  = "service.alpha.openshift.io/inject-cabundle"
	injectCABundleAnnotationValue = "true"
)

func (c *authOperator) handleServiceCA() (*corev1.ConfigMap, error) {
	cm := c.configMaps.ConfigMaps(targetName)
	serviceCA, err := cm.Get(serviceCAName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		serviceCA, err = cm.Create(defaultServiceCA())
	}
	if err != nil {
		return nil, err
	}

	if len(serviceCA.Data[serviceCAKey]) == 0 {
		return nil, fmt.Errorf("config map has no service ca data: %#v", serviceCA)
	}

	if err := isValidServiceCA(serviceCA); err != nil {
		// delete the service CA config map so that it is replaced with the proper one in next reconcile loop
		glog.Infof("deleting invalid service CA config map: %#v", serviceCA)
		opts := &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &serviceCA.UID}}
		if err := cm.Delete(serviceCA.Name, opts); err != nil && !errors.IsNotFound(err) {
			glog.Infof("failed to delete invalid service CA config map: %v", err)
		}
		return nil, err
	}

	return serviceCA, nil
}

func isValidServiceCA(ca *corev1.ConfigMap) error {
	if ca.Annotations[injectCABundleAnnotationName] != injectCABundleAnnotationValue {
		return fmt.Errorf("config map missing injection annotation: %#v", ca)
	}
	return nil
}

func defaultServiceCA() *corev1.ConfigMap {
	meta := defaultMeta()
	meta.Name = serviceCAName
	meta.Annotations[injectCABundleAnnotationName] = injectCABundleAnnotationValue
	return &corev1.ConfigMap{
		ObjectMeta: meta,
	}
}
