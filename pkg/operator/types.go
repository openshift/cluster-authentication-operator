package operator

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// partial copies from installer

type InstallConfig struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ObjectMeta `json:"metadata"`

	// BaseDomain is the base domain to which the cluster should belong.
	BaseDomain string `json:"baseDomain"`
}

func getAPIServerURL(ic *InstallConfig) string {
	return fmt.Sprintf("https://%s-api.%s:6443", ic.ObjectMeta.Name, ic.BaseDomain)
}

//
//// partial copies from cluster-kube-apiserver-operator
//
//type KubeAPIServerOperatorConfig struct {
//	metav1.TypeMeta   `json:",inline"`
//	metav1.ObjectMeta `json:"metadata"`
//
//	Spec KubeAPIServerOperatorConfigSpec `json:"spec"`
//}
//
//type KubeAPIServerOperatorConfigSpec struct {
//	operatorsv1.OperatorSpec `json:",inline"`
//}
