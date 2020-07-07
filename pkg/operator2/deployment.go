package operator2

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog"

	"github.com/ghodss/yaml"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
	observeoauth "github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation/oauth"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/assets"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/datasync"
)

func defaultDeployment(
	operatorConfig *operatorv1.Authentication,
	proxyConfig *configv1.Proxy,
	bootstrapUserExists bool,
	resourceVersions ...string,
) (*appsv1.Deployment, error) {

	// load deployment
	deployment := resourceread.ReadDeploymentV1OrDie(assets.MustAsset("oauth-openshift/deployment.yaml"))

	// force redeploy when any associated resource changes
	// we use a hash to prevent this value from growing indefinitely
	// need to sort first in order to get a stable array
	sort.Strings(resourceVersions)
	rvs := strings.Join(resourceVersions, ",")
	klog.V(4).Infof("tracked resource versions: %s", rvs)
	rvsHash := sha512.Sum512([]byte(rvs))
	rvsHashStr := base64.RawURLEncoding.EncodeToString(rvsHash[:])
	if deployment.Annotations == nil {
		deployment.Annotations = map[string]string{}
	}
	deployment.Annotations[deploymentVersionHashKey] = rvsHashStr

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[deploymentVersionHashKey] = rvsHashStr

	// Ensure a rollout when the bootstrap user goes away
	if bootstrapUserExists {
		deployment.Spec.Template.Annotations["operator.openshift.io/bootstrap-user-exists"] = "true"
	}

	templateSpec := &deployment.Spec.Template.Spec
	container := &templateSpec.Containers[0]

	// image spec
	if container.Image == "${IMAGE}" {
		container.Image = oauthserverImage
	}

	// set proxy env vars
	container.Env = append(container.Env, proxyConfigToEnvVars(proxyConfig)...)

	// set log level
	container.Args[0] = strings.Replace(container.Args[0], "${LOG_LEVEL}", fmt.Sprintf("%d", getLogLevel(operatorConfig.Spec.LogLevel)), -1)

	idpSyncData, err := getSyncDataFromOperatorConfig(&operatorConfig.Spec.ObservedConfig)
	if err != nil {
		return nil, fmt.Errorf("couldn't retrieve volumes to mount to the container from the observed config: %v", err)
	}

	// mount more secrets and config maps
	v, m, err := idpSyncData.ToVolumesAndMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to transform observed sync data to volumes and mounts: %w", err)
	}
	templateSpec.Volumes = append(templateSpec.Volumes, v...)
	container.VolumeMounts = append(container.VolumeMounts, m...)

	return deployment, nil
}

// grabPrefixedConfig returns the configuration from the operator's observedConfig field
// in the subtree given by the prefix
// DEPRECATED: Do not use, this will be removed.
func grabPrefixedConfig(observedBytes []byte, prefix ...string) ([]byte, error) {
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

func getSyncDataFromOperatorConfig(operatorConfig *runtime.RawExtension) (*datasync.ConfigSyncData, error) {
	var configDeserialized map[string]interface{}
	oauthServerObservedConfig, err := grabPrefixedConfig(operatorConfig.Raw, configobservation.OAuthServerConfigPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to grab the operator config: %w", err)
	}

	if err := yaml.Unmarshal(oauthServerObservedConfig, &configDeserialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the observedConfig: %v", err)
	}

	return observeoauth.GetIDPConfigSyncData(configDeserialized)
}

func getLogLevel(logLevel operatorv1.LogLevel) int {
	switch logLevel {
	case operatorv1.Normal, "": // treat empty string to mean the default
		return 2
	case operatorv1.Debug:
		return 4
	case operatorv1.Trace:
		return 6
	case operatorv1.TraceAll:
		return 100 // this is supposed to be 8 but I prefer "all" to really mean all
	default:
		return 0
	}
}

func proxyConfigToEnvVars(proxy *configv1.Proxy) []corev1.EnvVar {
	var envVars []corev1.EnvVar
	envVars = appendEnvVar(envVars, "NO_PROXY", proxy.Status.NoProxy)
	envVars = appendEnvVar(envVars, "HTTP_PROXY", proxy.Status.HTTPProxy)
	envVars = appendEnvVar(envVars, "HTTPS_PROXY", proxy.Status.HTTPSProxy)
	return envVars
}

func appendEnvVar(envVars []corev1.EnvVar, envName, envVal string) []corev1.EnvVar {
	if len(envVal) > 0 {
		return append(envVars, corev1.EnvVar{Name: envName, Value: envVal})
	}
	return envVars
}
