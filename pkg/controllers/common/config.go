package common

import (
	"bytes"
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
)

// UnstructuredConfigFrom returns the configuration from the operator's observedConfig field in the subtree given by the prefix
func UnstructuredConfigFrom(observedBytes []byte, prefix ...string) ([]byte, error) {
	if len(prefix) == 0 {
		return observedBytes, nil
	}

	prefixedConfig := map[string]interface{}{}
	if err := json.NewDecoder(bytes.NewBuffer(observedBytes)).Decode(&prefixedConfig); err != nil {
		klog.V(4).Infof("decode of existing config failed with error: %v", err)
	}

	actualConfig, _, err := unstructured.NestedFieldCopy(prefixedConfig, prefix...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(actualConfig)
}

// TODO: this should be in library-go
func NamesFilter(names ...string) factory.EventFilterFunc {
	nameSet := sets.NewString(names...)
	return func(obj interface{}) bool {
		metaObj, ok := obj.(metav1.ObjectMetaAccessor)
		if !ok {
			return false
		}
		return nameSet.Has(metaObj.GetObjectMeta().GetName())
	}
}
