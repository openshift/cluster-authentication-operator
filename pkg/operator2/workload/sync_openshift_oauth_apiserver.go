package workload

import (
	"encoding/json"
	"fmt"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/apiserver-library-go/pkg/configflags"
	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/operator2/assets"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"regexp"
	"strings"
)

// OAuthAPIServerWorkload a struct that holds necessary data to install OAuthAPIServer
type OAuthAPIServerWorkload struct {
	operatorClient        operatorconfigclient.AuthenticationsGetter
	targetNamespace       string
	targetImagePullSpec   string
	operatorImagePullSpec string
	kubeClient            kubernetes.Interface
	eventRecorder         events.Recorder
	versionRecorder       status.VersionGetter
}

// NewOAuthAPIServerWorkload creates new OAuthAPIServerWorkload struct
func NewOAuthAPIServerWorkload(
	operatorClient operatorconfigclient.AuthenticationsGetter,
	targetNamespace string,
	targetImagePullSpec string,
	operatorImagePullSpec string,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
	versionRecorder status.VersionGetter,
) *OAuthAPIServerWorkload {
	return &OAuthAPIServerWorkload{
		operatorClient:        operatorClient,
		targetNamespace:       targetNamespace,
		targetImagePullSpec:   targetImagePullSpec,
		operatorImagePullSpec: operatorImagePullSpec,
		kubeClient:            kubeClient,
		eventRecorder:         eventRecorder,
		versionRecorder:       versionRecorder,
	}
}

// Sync essentially manages OAuthAPI server.
func (c *OAuthAPIServerWorkload) Sync() (*appsv1.DaemonSet, []error) {
	errs := []error{}

	authOperator, err := c.operatorClient.Authentications().Get("cluster", metav1.GetOptions{})
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	// TODO: block until config is obvserved when required
	/*if operatorCfg, err := getStructuredConfig(authOperator.Spec.OperatorSpec); err != nil {
		errs = append(errs, err)
		return nil, errs
	} else {
		if len(operatorCfg.APIServerArguments) == 0 {
			klog.Info("Waiting for observed configuration to be available")
			errs = append(errs, errors.New("waiting for observed configuration to be available (spec.ObservedConfig.Raw)"))
			return nil, errs
		}
	}*/

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

	actualDaemonSet, err := c.syncDaemonSet(authOperator, authOperator.Status.Generations)
	if err != nil {
		errs = append(errs, fmt.Errorf("%q: %v", "daemonsets", err))
	}
	return actualDaemonSet, errs
}

func (c *OAuthAPIServerWorkload) syncDaemonSet(authOperator *operatorv1.Authentication, generationStatus []operatorv1.GenerationStatus) (*appsv1.DaemonSet, error) {
	tmpl, err := assets.Asset("oauth-apiserver/ds.yaml")
	if err != nil {
		return nil, err
	}

	operatorCfg, err := getStructuredConfig(authOperator.Spec.OperatorSpec)
	if err != nil {
		return nil, err
	}

	// log level verbosity is taken from the spec always
	operatorCfg.APIServerArguments["v"] = []string{loglevelToKlog(authOperator.Spec.LogLevel)}
	operandFlags := configflags.ToFlagSlice(operatorCfg.APIServerArguments)

	r := strings.NewReplacer(
		"${IMAGE}", c.targetImagePullSpec,
		// TODO: add LatestAvailableRevision support
		//"${REVISION}", strconv.Itoa(int(authOperator.Status.LatestAvailableRevision)),
		"${REVISION}", "1",
		"${FLAGS}", strings.Join(padFlags(operandFlags, strings.Repeat(" ", 14)), " \\\n"),
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

// oAuthAPIServerConfig hold configuration for this controller it's taken from ObservedConfig.Raw
// note that this struct is unsupported in a sense that it's not exposed through API
type oAuthAPIServerConfig struct {
	APIServerArguments map[string][]string `json:"apiServerArguments"`
}

// unstructuredConfigFrom extract raw config for this controller
func unstructuredConfigFrom(rawCfg []byte) ([]byte, error) {
	configJSON, err := kyaml.ToJSON(rawCfg)
	if err != nil {
		return nil, err
	}
	configMap := map[string]interface{}{}
	if err := json.Unmarshal(configJSON, &configMap); err != nil {
		return nil, err
	}

	oauthAPIServerCfg, ok := configMap["oauthAPIServer"]
	if !ok {
		return nil, nil
	}

	oauthAPIServerRaw, err := json.Marshal(oauthAPIServerCfg)
	if err != nil {
		return nil, err
	}
	return oauthAPIServerRaw, nil
}

// getStructuredConfig reads and merges configs for this controller from ObservedConfig.Raw and UnsupportedConfigOverrides.Raw,
// merged config is then encoded into oAuthAPIServerConfig struct
func getStructuredConfig(authOperatorSpec operatorv1.OperatorSpec) (*oAuthAPIServerConfig, error) {
	unstructuredCfg, err := unstructuredConfigFrom(authOperatorSpec.ObservedConfig.Raw)
	if err != nil {
		return nil, err
	}

	unstructuredUnsupportedCfg, err := unstructuredConfigFrom(authOperatorSpec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return nil, err
	}

	unstructuredMergedCfg, err := resourcemerge.MergeProcessConfig(
		nil,
		unstructuredCfg,
		unstructuredUnsupportedCfg,
	)
	if err != nil {
		return nil, err
	}

	cfg := &oAuthAPIServerConfig{}
	if err := json.Unmarshal(unstructuredMergedCfg, cfg); err != nil {
		return nil, err
	}

	if cfg.APIServerArguments == nil {
		cfg.APIServerArguments = map[string][]string{}
	}

	return cfg, nil
}

// padFlags appends "appendString" to each flag except the first one
func padFlags(flags []string, appendString string) []string {
	if len(flags) <= 1 {
		return flags
	}
	paddedFlags := make([]string, len(flags))
	paddedFlags[0] = flags[0]

	flags = flags[1:]
	for index, flag := range flags {
		index++
		paddedFlags[index] = fmt.Sprintf("%s%s", appendString, flag)
	}

	return paddedFlags
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
