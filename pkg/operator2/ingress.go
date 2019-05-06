package operator2

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func (c *authOperator) handleIngress() (*configv1.Ingress, error) {
	ingress, err := c.ingress.Get(globalConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if len(ingress.Spec.Domain) == 0 {
		return nil, fmt.Errorf("ingress has empty spec.domain: %#v", ingress)
	}
	return ingress, nil
}
