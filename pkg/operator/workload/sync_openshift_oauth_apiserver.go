package workload

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/operator/assets"
	oauthapiconfigobserver "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
	"github.com/openshift/library-go/pkg/controller/factory"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// shellEscapePattern determines if a string should be enclosed in single quotes
// so that it can safely be passed to shell command line.
var shellEscapePattern *regexp.Regexp

func init() {
	shellEscapePattern = regexp.MustCompile(`[^\w@%+=:,./-]`)
}

// nodeCountFunction a function to return count of nodes
type nodeCountFunc func(nodeSelector map[string]string) (*int32, error)

// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
// one pod of a given replicaset from landing on a node.
type ensureAtMostOnePodPerNodeFunc func(spec *appsv1.DeploymentSpec, componentName string) error

// OAuthAPIServerWorkload is a struct that holds necessary data to install OAuthAPIServer
type OAuthAPIServerWorkload struct {
	operatorClient operatorconfigclient.AuthenticationsGetter
	// countNodes a function to return count of nodes on which the workload will be installed
	countNodes nodeCountFunc
	// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
	// one pod of a given replicaset from landing on a node.
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc
	targetNamespace           string
	targetImagePullSpec       string
	operatorImagePullSpec     string
	kubeClient                kubernetes.Interface
	versionRecorder           status.VersionGetter
}

// NewOAuthAPIServerWorkload creates new OAuthAPIServerWorkload struct
func NewOAuthAPIServerWorkload(
	operatorClient operatorconfigclient.AuthenticationsGetter,
	countNodes nodeCountFunc,
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc,
	targetNamespace string,
	targetImagePullSpec string,
	operatorImagePullSpec string,
	kubeClient kubernetes.Interface,
	versionRecorder status.VersionGetter,
) *OAuthAPIServerWorkload {
	return &OAuthAPIServerWorkload{
		operatorClient:            operatorClient,
		countNodes:                countNodes,
		ensureAtMostOnePodPerNode: ensureAtMostOnePodPerNode,
		targetNamespace:           targetNamespace,
		targetImagePullSpec:       targetImagePullSpec,
		operatorImagePullSpec:     operatorImagePullSpec,
		kubeClient:                kubeClient,
		versionRecorder:           versionRecorder,
	}
}

// PreconditionFulfilled is a function that indicates whether all prerequisites are met and we can Sync.
func (c *OAuthAPIServerWorkload) PreconditionFulfilled(ctx context.Context) (bool, error) {
	authOperator, err := c.operatorClient.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	return c.preconditionFulfilledInternal(authOperator)
}

func (c *OAuthAPIServerWorkload) preconditionFulfilledInternal(authOperator *operatorv1.Authentication) (bool, error) {
	operatorCfg, err := getStructuredConfig(authOperator.Spec.OperatorSpec)
	if err != nil {
		return false, err
	}

	if len(operatorCfg.APIServerArguments) == 0 {
		klog.Info("Waiting for observed configuration to be available")
		return false, fmt.Errorf("waiting for observed configuration to be available (haven't found APIServerArguments in spec.ObservedConfig.Raw)")
	}

	// specifying etcd servers list is mandatory, without it the pods will be crashlooping, so wait for it.
	if storageServers := operatorCfg.APIServerArguments[libgoetcd.StorageConfigURLsKey]; len(storageServers) == 0 {
		klog.Infof("Waiting for observed configuration to have mandatory apiServerArguments.%s", libgoetcd.StorageConfigURLsKey)
		return false, fmt.Errorf("waiting for observed configuration to have mandatory apiServerArguments.%s", libgoetcd.StorageConfigURLsKey)
	}
	return true, nil
}

// Sync essentially manages OAuthAPI server.
func (c *OAuthAPIServerWorkload) Sync(ctx context.Context, syncCtx factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	errs := []error{}

	authOperator, err := c.operatorClient.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		errs = append(errs, err)
		return nil, false, errs
	}

	actualDeployment, err := c.syncDeployment(authOperator, authOperator.Status.Generations, syncCtx.Recorder())
	if err != nil {
		errs = append(errs, fmt.Errorf("%q: %v", "deployments", err))
	}
	return actualDeployment, true, errs
}

func (c *OAuthAPIServerWorkload) syncDeployment(authOperator *operatorv1.Authentication, generationStatus []operatorv1.GenerationStatus, eventRecorder events.Recorder) (*appsv1.Deployment, error) {
	tmpl, err := assets.Asset("oauth-apiserver/deploy.yaml")
	if err != nil {
		return nil, err
	}

	operatorCfg, err := getStructuredConfigWithDefaultValues(authOperator.Spec.OperatorSpec)
	if err != nil {
		return nil, err
	}

	// log level verbosity is taken from the spec always
	operatorCfg.APIServerArguments["v"] = []string{loglevelToKlog(authOperator.Spec.LogLevel)}
	operandFlags := toFlagSlice(operatorCfg.APIServerArguments)

	// use string replacer for simple things
	r := strings.NewReplacer(
		"${IMAGE}", c.targetImagePullSpec,
		"${REVISION}", strconv.Itoa(int(authOperator.Status.OAuthAPIServer.LatestAvailableRevision)),
	)

	excludedReferences := sets.NewString("${FLAGS}")
	tmpl = []byte(r.Replace(string(tmpl)))
	re := regexp.MustCompile("\\$\\{[^}]*}")
	if match := re.Find(tmpl); len(match) > 0 && !excludedReferences.Has(string(match)) {
		return nil, fmt.Errorf("invalid template reference %q", string(match))
	}

	required := resourceread.ReadDeploymentV1OrDie(tmpl)

	// use the following routine for things that would require special formatting/padding (yaml)
	r = strings.NewReplacer(
		"${FLAGS}", strings.Join(operandFlags, " \\\n"),
	)
	for containerIndex, container := range required.Spec.Template.Spec.Containers {
		for argIndex, arg := range container.Args {
			required.Spec.Template.Spec.Containers[containerIndex].Args[argIndex] = r.Replace(arg)
		}
	}
	for initContainerIndex, initContainer := range required.Spec.Template.Spec.InitContainers {
		for argIndex, arg := range initContainer.Args {
			required.Spec.Template.Spec.InitContainers[initContainerIndex].Args[argIndex] = r.Replace(arg)
		}
	}

	// we set this so that when the requested image pull spec changes, we always have a diff.  Remember that we don't directly
	// diff any fields on the deployment because they can be rewritten by admission and we don't want to constantly be fighting
	// against admission or defaults.  That was a problem with original versions of apply.
	if required.Annotations == nil {
		required.Annotations = map[string]string{}
	}
	required.Annotations["openshiftapiservers.operator.openshift.io/operator-pull-spec"] = c.operatorImagePullSpec

	required.Labels["revision"] = strconv.Itoa(int(authOperator.Status.OAuthAPIServer.LatestAvailableRevision))
	required.Spec.Template.Labels["revision"] = strconv.Itoa(int(authOperator.Status.OAuthAPIServer.LatestAvailableRevision))

	// we watch some resources so that our deployment will redeploy without explicitly and carefully ordered resource creation
	inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferences(
		c.kubeClient,
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

	// Set the replica count to the number of master nodes.
	masterNodeCount, err := c.countNodes(required.Spec.Template.Spec.NodeSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to determine number of master nodes: %v", err)
	}
	required.Spec.Replicas = masterNodeCount

	zero := intstr.FromInt(0)
	one := intstr.FromInt(1)
	if masterNodeCount != nil && *masterNodeCount == 1 {
		// single-node
		required.Spec.Strategy = appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxUnavailable: &zero,
				MaxSurge:       &one,
			},
		}
	} else {
		// HA mode
		required.Spec.Strategy = appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxUnavailable: &one,
				MaxSurge:       &zero,
			},
		}

		err = c.ensureAtMostOnePodPerNode(&required.Spec, "oauth-apiserver")
		if err != nil {
			return nil, fmt.Errorf("unable to ensure at most one pod per node: %v", err)
		}
	}

	deployment, _, err := resourceapply.ApplyDeployment(c.kubeClient.AppsV1(), eventRecorder, required, resourcemerge.ExpectedDeploymentGeneration(required, generationStatus))
	return deployment, err
}

// oAuthAPIServerConfig hold configuration for this controller it's taken from ObservedConfig.Raw
// note that this struct is unsupported in a sense that it's not exposed through API
type oAuthAPIServerConfig struct {
	APIServerArguments map[string][]string `json:"apiServerArguments"`
}

func getStructuredConfigWithDefaultValues(authOperatorSpec operatorv1.OperatorSpec) (*oAuthAPIServerConfig, error) {
	operatorCfg, err := getStructuredConfig(authOperatorSpec)
	if err != nil {
		return nil, err
	}

	defaultAPIServerArguments := map[string][]string{
		"audit-policy-file": {"/var/run/configmaps/audit/default.yaml"},
		"api-audiences":     {"https://kubernetes.default.svc"},
	}

	for defArgName, defArgValue := range defaultAPIServerArguments {
		if _, ok := operatorCfg.APIServerArguments[defArgName]; !ok {
			operatorCfg.APIServerArguments[defArgName] = defArgValue
		}
	}

	return operatorCfg, nil
}

// merged config is then encoded into oAuthAPIServerConfig struct
func getStructuredConfig(authOperatorSpec operatorv1.OperatorSpec) (*oAuthAPIServerConfig, error) {
	unstructuredCfg, err := common.UnstructuredConfigFrom(authOperatorSpec.ObservedConfig.Raw, oauthapiconfigobserver.OAuthAPIServerConfigPrefix)
	if err != nil {
		return nil, err
	}

	unstructuredUnsupportedCfg, err := common.UnstructuredConfigFrom(authOperatorSpec.UnsupportedConfigOverrides.Raw, oauthapiconfigobserver.OAuthAPIServerConfigPrefix)
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

	type unstructuredOAuthAPIServerConfig struct {
		APIServerArguments map[string]interface{} `json:"apiServerArguments"`
	}

	cfgUnstructured := &unstructuredOAuthAPIServerConfig{}
	if err := json.Unmarshal(unstructuredMergedCfg, cfgUnstructured); err != nil {
		return nil, err
	}

	cfg := &oAuthAPIServerConfig{}
	cfg.APIServerArguments = map[string][]string{}
	for argName, argRawValue := range cfgUnstructured.APIServerArguments {
		var argsSlice []string
		var found bool
		var err error

		argsSlice, found, err = unstructured.NestedStringSlice(cfgUnstructured.APIServerArguments, argName)
		if !found || err != nil {
			str, found, err := unstructured.NestedString(cfgUnstructured.APIServerArguments, argName)
			if !found || err != nil {
				return nil, fmt.Errorf("unable to create OAuthConfig, incorrect value %v under %v key, expected []string or string", argRawValue, argName)
			}
			argsSlice = append(argsSlice, str)
		}

		escapedArgsSlice := make([]string, len(argsSlice))
		for index, str := range argsSlice {
			escapedArgsSlice[index] = maybeQuote(str)
		}

		cfg.APIServerArguments[argName] = escapedArgsSlice
	}

	return cfg, nil
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

// maybeQuote returns a shell-escaped version of the string s. The returned value
// is a string that can safely be used as one token in a shell command line.
//
// note: this method was copied from https://github.com/alessio/shellescape/blob/0d13ae33b78a20a5d91c54ca7e216e1b75aaedef/shellescape.go#L30
func maybeQuote(s string) string {
	if len(s) == 0 {
		return "''"
	}
	if shellEscapePattern.MatchString(s) {
		return "'" + strings.Replace(s, "'", "'\"'\"'", -1) + "'"
	}

	return s
}

// taken from apiserver-library-go so that we don't pull k/k dep to this repo
func toFlagSlice(args map[string][]string) []string {
	var keys []string
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var flags []string
	for _, key := range keys {
		for _, token := range args[key] {
			flags = append(flags, fmt.Sprintf("--%s=%v", key, token))
		}
	}
	return flags
}
