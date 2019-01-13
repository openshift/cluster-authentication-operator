package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/api/operator/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationOperatorConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthenticationOperatorConfigSpec   `json:"spec,omitempty"`
	Status AuthenticationOperatorConfigStatus `json:"status,omitempty"`
}

type AuthenticationOperatorConfigSpec struct {
	v1.OperatorSpec
}

type AuthenticationOperatorConfigStatus struct {
	v1.OperatorStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationOperatorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AuthenticationOperatorConfig `json:"items"`
}
