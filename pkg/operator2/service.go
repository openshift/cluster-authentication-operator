package operator2

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func defaultService() *v1.Service {
	return &v1.Service{
		ObjectMeta: defaultMeta(),
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(443),
				},
			},
			Selector:        defaultLabels(),
			Type:            "ClusterIP",
			SessionAffinity: "None",
		},
	}
}
