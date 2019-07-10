package nokey

import (
	"monis.app/go/openshift/operator"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ operator.KeySyncer = SyncFunc(nil)

// TODO move this into boilerplate library if it ends up being reusable
type SyncFunc func() error

func (f SyncFunc) Key() (metav1.Object, error) {
	return nil, nil
}

func (f SyncFunc) Sync(_ metav1.Object) error {
	return f()
}
