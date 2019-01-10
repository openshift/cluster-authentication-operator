package operator2

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func defaultService() *v1.Service {
	meta := defaultMeta()
	meta.Annotations["service.alpha.openshift.io/serving-cert-secret-name"] = servingCertName
	return &v1.Service{
		ObjectMeta: meta,
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(servicePort),
				},
			},
			Selector:        defaultLabels(),
			Type:            "ClusterIP",
			SessionAffinity: "None",
		},
	}
}
