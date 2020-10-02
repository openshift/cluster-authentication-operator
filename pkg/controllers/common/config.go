package common

import (
	"bytes"
	"encoding/json"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
