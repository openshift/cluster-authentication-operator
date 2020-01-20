package workload

import (
	"fmt"
	operatorv1 "github.com/openshift/api/operator/v1"
	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/assets"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"regexp"
	"sort"
	"strings"
)

type OpenShiftOAuthAPIServerManager struct {
	operatorClient        operatorconfigclient.AuthenticationsGetter
	targetNamespace       string
	targetImagePullSpec   string
	operatorImagePullSpec string
	kubeClient            kubernetes.Interface
	eventRecorder         events.Recorder
	versionRecorder       status.VersionGetter
}

func NewOpenShiftOAuthAPIServerManager(
	operatorClient operatorconfigclient.AuthenticationsGetter,
	targetNamespace string,
	targetImagePullSpec string,
	operatorImagePullSpec string,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
	versionRecorder status.VersionGetter,
) *OpenShiftOAuthAPIServerManager {
	return &OpenShiftOAuthAPIServerManager{
		operatorClient:        operatorClient,
		targetNamespace:       targetNamespace,
		targetImagePullSpec:   targetImagePullSpec,
		operatorImagePullSpec: operatorImagePullSpec,
		kubeClient:            kubeClient,
		eventRecorder:         eventRecorder,
		versionRecorder:       versionRecorder,
	}
}

func (c *OpenShiftOAuthAPIServerManager) SyncOpenShiftOAuthAPIServer() (*appsv1.DaemonSet, []error) {
	errs := []error{}

	authOperator, err := c.operatorClient.Authentications().Get("cluster", metav1.GetOptions{})
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	// manage assets
	directResourceResults := resourceapply.ApplyDirectly(c.kubeClient, c.eventRecorder, assets.Asset,
		"oauth-apiserver/ns.yaml",
		"oauth-apiserver/apiserver-clusterrolebinding.yaml",
		"oauth-apiserver/svc.yaml",
		"oauth-apiserver/sa.yaml",
		"oauth-apiserver/cm.yaml",
	)
	for _, currResult := range directResourceResults {
		if currResult.Error != nil {
			errs = append(errs, fmt.Errorf("%q (%T): %v", currResult.File, currResult.Type, currResult.Error))
		}
	}

	actualDaemonSet, err := c.syncOpenShiftOAuthAPIServerDaemonSet(authOperator, authOperator.Status.Generations)
	if err != nil {
		errs = append(errs, fmt.Errorf("%q: %v", "daemonsets", err))
	}
	return actualDaemonSet, errs
}

func (c *OpenShiftOAuthAPIServerManager) syncOpenShiftOAuthAPIServerDaemonSet(authOperator *operatorv1.Authentication, generationStatus []operatorv1.GenerationStatus) (*appsv1.DaemonSet, error) {
	tmpl, err := assets.Asset("oauth-apiserver/ds.yaml")
	if err != nil {
		return nil, err
	}

	r := strings.NewReplacer(
		"${IMAGE}", c.targetImagePullSpec,
		"${OPERATOR_IMAGE}", c.operatorImagePullSpec,
		// TODO: add LatestAvailableRevision support
		//"${REVISION}", strconv.Itoa(int(authOperator.Status.LatestAvailableRevision)),
		"${REVISION}", "1",
		"${VERBOSITY}", loglevelToKlog(authOperator.Spec.LogLevel),
	)
	tmpl = []byte(r.Replace(string(tmpl)))

	re := regexp.MustCompile("\\$\\{[^}]*}")
	if match := re.Find(tmpl); len(match) > 0 {
		return nil, fmt.Errorf("invalid template reference %q", string(match))
	}

	required := resourceread.ReadDaemonSetV1OrDie(tmpl)

	// we set this so that when the requested image pull spec changes, we always have a diff.  Remember that we don't directly
	// diff any fields on the daemonset because they can be rewritten by admission and we don't want to constantly be fighting
	// against admission or defaults.  That was a problem with original versions of apply.
	if required.Annotations == nil {
		required.Annotations = map[string]string{}
	}
	required.Annotations["openshiftapiservers.operator.openshift.io/pull-spec"] = c.targetImagePullSpec
	required.Annotations["openshiftapiservers.operator.openshift.io/operator-pull-spec"] = c.operatorImagePullSpec

	// TODO: add LatestAvailableRevision support
	//required.Labels["revision"] = strconv.Itoa(int(authOperator.Status.LatestAvailableRevision))
	//required.Spec.Template.Labels["revision"] = strconv.Itoa(int(authOperator.Status.LatestAvailableRevision))

	// TODO: Spec.ObservedConfig.Raw exists and has desired data
	//var observedConfig map[string]interface{}
	/*if err := yaml.Unmarshal(authOperator.Spec.ObservedConfig.Raw, &observedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the observedConfig: %v", err)
	}
	proxyConfig, _, err := unstructured.NestedStringMap(observedConfig, "workloadcontroller", "proxy")
	if err != nil {
		return nil, fmt.Errorf("couldn't get the proxy config from observedConfig: %v", err)
	}

	proxyEnvVars := proxyMapToEnvVars(proxyConfig)
	for i, container := range required.Spec.Template.Spec.Containers {
		required.Spec.Template.Spec.Containers[i].Env = append(container.Env, proxyEnvVars...)
	}*/

	// we watch some resources so that our daemonset will redeploy without explicitly and carefully ordered resource creation
	inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferences(
		c.kubeClient,
		resourcehash.NewObjectRef().ForConfigMap().InNamespace(c.targetNamespace).Named("config"),
		resourcehash.NewObjectRef().ForSecret().InNamespace(c.targetNamespace).Named("etcd-client"),
		resourcehash.NewObjectRef().ForConfigMap().InNamespace(c.targetNamespace).Named("etcd-serving-ca"),
		resourcehash.NewObjectRef().ForConfigMap().InNamespace(c.targetNamespace).Named("trusted-ca-bundle"),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid dependency reference: %q", err)
	}

	for k, v := range inputHashes {
		annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
		required.Annotations[annotationKey] = v
		if required.Spec.Template.Annotations == nil {
			required.Spec.Template.Annotations = map[string]string{}
		}
		required.Spec.Template.Annotations[annotationKey] = v
	}

	ds, _, err := resourceapply.ApplyDaemonSet(c.kubeClient.AppsV1(), c.eventRecorder, required, resourcemerge.ExpectedDaemonSetGeneration(required, generationStatus), false)
	return ds, err
}

func loglevelToKlog(logLevel operatorv1.LogLevel) string {
	switch logLevel {
	case operatorv1.Normal:
		return "2"
	case operatorv1.Debug:
		return "4"
	case operatorv1.Trace:
		return "6"
	case operatorv1.TraceAll:
		return "8"
	default:
		return "2"
	}
}

func proxyMapToEnvVars(proxyConfig map[string]string) []corev1.EnvVar {
	if proxyConfig == nil {
		return nil
	}

	envVars := []corev1.EnvVar{}
	for k, v := range proxyConfig {
		envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
	}

	// sort the env vars to prevent update hotloops
	sort.Slice(envVars, func(i, j int) bool { return envVars[i].Name < envVars[j].Name })
	return envVars
}
