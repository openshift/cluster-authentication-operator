package operator2

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/openshift/cluster-authentication-operator/pkg/utils"
)

func defaultService() *v1.Service {
	meta := utils.DefaultMetaOAuthServerResources()
	meta.Annotations["service.alpha.openshift.io/serving-cert-secret-name"] = "v4-0-config-system-serving-cert"
	return &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			// If more than one port is needed for this service, make
			// sure to update IngressStateController to support more
			// than a single subset. Only if more than one port is
			// exposed by this service is it possible for the
			// resulting endpoints resource to have more than one
			// subset.
			Ports: []v1.ServicePort{
				{
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(6443),
				},
			},
			Selector:        utils.DefaultLabelsOAuthServerResources(),
			Type:            "ClusterIP",
			SessionAffinity: "None",
		},
	}
}
