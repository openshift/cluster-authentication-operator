package readiness

import (
	"bytes"
	"encoding/json"
	"strconv"

	configv1 "github.com/openshift/api/config/v1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	operatorv1 "github.com/openshift/api/operator/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"
)

// isUnsupportedUnsafeAuthentication returns true if
// useUnsupportedUnsafeNonHANonProductionUnstableOAuthServer key is set
// to any parsable true value
func isUnsupportedUnsafeAuthentication(spec *operatorv1.OperatorSpec) (bool, error) {
	unsupportedConfig := map[string]interface{}{}
	if spec.UnsupportedConfigOverrides.Raw == nil {
		return false, nil
	}

	configJson, err := kyaml.ToJSON(spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		klog.Warning(err)
		// maybe it's just json
		configJson = spec.UnsupportedConfigOverrides.Raw
	}

	if err := json.NewDecoder(bytes.NewBuffer(configJson)).Decode(&unsupportedConfig); err != nil {
		klog.V(4).Infof("decode of unsupported config failed with error: %v", err)
		return false, err
	}

	// 1. this violates operational best practices for authentication - unstable
	// 2. this allows configuration to vary between kube-apiservers - unsafe and non-HA, non-production
	// 3. the combination of all these things makes the situation unsupportable.
	value, found, err := unstructured.NestedFieldNoCopy(unsupportedConfig, "useUnsupportedUnsafeNonHANonProductionUnstableOAuthServer")
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	switch value.(type) {
	case bool:
		return value.(bool), nil
	case string:
		return strconv.ParseBool(value.(string))
	default:
		return false, nil
	}
}

func getExpectedMinimumNumberOfMasters(spec *operatorv1.OperatorSpec, topologyMode configv1.TopologyMode) int {
	allowAnyNumber, err := isUnsupportedUnsafeAuthentication(spec)
	switch {
	case topologyMode == configv1.SingleReplicaTopologyMode:
		return 1
	case topologyMode == configv1.HighlyAvailableArbiterMode:
		return 2
	case err != nil:
		utilruntime.HandleError(err)
		return 3
	case allowAnyNumber:
		return 1
	default:
		return 3
	}
}
