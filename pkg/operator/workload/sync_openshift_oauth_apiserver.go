package workload

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/openshift/library-go/pkg/operator/v1helpers"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"

	"github.com/openshift/cluster-authentication-operator/bindata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common/arguments"
	oauthapiconfigobservercontroller "github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation/configobservercontroller"
)

// nodeCountFunction a function to return count of nodes
type nodeCountFunc func(nodeSelector map[string]string) (*int32, error)

// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
// one pod of a given replicaset from landing on a node.
type ensureAtMostOnePodPerNodeFunc func(spec *appsv1.DeploymentSpec, componentName string) error

// OAuthAPIServerWorkload is a struct that holds necessary data to install OAuthAPIServer
type OAuthAPIServerWorkload struct {
	operatorClient v1helpers.OperatorClient
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
	authConfigChecker         common.AuthConfigChecker
}

// NewOAuthAPIServerWorkload creates new OAuthAPIServerWorkload struct
func NewOAuthAPIServerWorkload(
	operatorClient v1helpers.OperatorClient,
	countNodes nodeCountFunc,
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc,
	targetNamespace string,
	targetImagePullSpec string,
	operatorImagePullSpec string,
	kubeClient kubernetes.Interface,
	authConfigChecker common.AuthConfigChecker,
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
		authConfigChecker:         authConfigChecker,
		versionRecorder:           versionRecorder,
	}
}

// PreconditionFulfilled is a function that indicates whether all prerequisites are met and we can Sync.
func (c *OAuthAPIServerWorkload) PreconditionFulfilled(ctx context.Context) (bool, error) {
	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return false, err
	}

	return c.preconditionFulfilledInternal(operatorSpec, operatorStatus)
}

func (c *OAuthAPIServerWorkload) preconditionFulfilledInternal(operatorSpec *operatorv1.OperatorSpec, operatorStatus *operatorv1.OperatorStatus) (bool, error) {
	if operatorStatus.LatestAvailableRevision == 0 {
		// this a backstop during the migration from 4.17 whe this information is in .status.oauthAPIServer.latestAvailableRevision
		return false, fmt.Errorf("waiting for .status.latestAvailableRevision to be available")
	}

	argsRaw, err := GetAPIServerArgumentsRaw(*operatorSpec)
	if err != nil {
		return false, err
	}

	args, err := arguments.Parse(argsRaw)
	if err != nil {
		return false, err
	}

	if len(args) == 0 {
		klog.Info("Waiting for observed configuration to be available")
		return false, fmt.Errorf("waiting for observed configuration to be available (haven't found APIServerArguments in spec.ObservedConfig.Raw)")
	}

	// specifying etcd servers list is mandatory, without it the pods will be crashlooping, so wait for it.
	if storageServers := args[libgoetcd.StorageConfigURLsKey]; len(storageServers) == 0 {
		klog.Infof("Waiting for observed configuration to have mandatory apiServerArguments.%s", libgoetcd.StorageConfigURLsKey)
		return false, fmt.Errorf("waiting for observed configuration to have mandatory apiServerArguments.%s", libgoetcd.StorageConfigURLsKey)
	}

	return true, nil
}

// Sync essentially manages OAuthAPI server.
func (c *OAuthAPIServerWorkload) Sync(ctx context.Context, syncCtx factory.SyncContext) (*appsv1.Deployment, bool, bool, string, string, []error) {
	errs := []error{}

	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		errs = append(errs, err)
		return nil, false, false, "", "", errs
	}

	actualDeployment, workloadDeleted, err := c.syncDeployment(ctx, operatorSpec, operatorStatus, syncCtx.Recorder())
	if err != nil {
		return actualDeployment, true, false, "", "", append(errs, fmt.Errorf("%q: %v", "deployments", err))
	} else if workloadDeleted {
		return nil, false, true, actualDeployment.Name, actualDeployment.Namespace, errs
	}

	return actualDeployment, true, false, "", "", errs
}

func (c *OAuthAPIServerWorkload) syncDeployment(ctx context.Context, operatorSpec *operatorv1.OperatorSpec, operatorStatus *operatorv1.OperatorStatus, eventRecorder events.Recorder) (*appsv1.Deployment, bool, error) {
	if operatorStatus.LatestAvailableRevision == 0 {
		// this a backstop during the migration from 4.17 whe this information is in .status.oauthAPIServer.latestAvailableRevision
		return nil, false, fmt.Errorf(".status.latestAvailableRevision is not yet available")
	}

	tmpl, err := bindata.Asset("oauth-apiserver/deploy.yaml")
	if err != nil {
		return nil, false, err
	}

	argsRaw, err := GetAPIServerArgumentsRaw(*operatorSpec)
	if err != nil {
		return nil, false, err
	}

	args, err := arguments.Parse(argsRaw)
	if err != nil {
		return nil, false, err
	}

	// log level verbosity is taken from the spec always
	args["v"] = []string{loglevelToKlog(operatorSpec.LogLevel)}

	// use string replacer for simple things
	r := strings.NewReplacer(
		"${IMAGE}", c.targetImagePullSpec,
		"${REVISION}", strconv.Itoa(int(operatorStatus.LatestAvailableRevision)),
	)

	excludedReferences := sets.NewString("${FLAGS}")
	tmpl = []byte(r.Replace(string(tmpl)))
	re := regexp.MustCompile(`\$\{[^}]*}`)
	if match := re.Find(tmpl); len(match) > 0 && !excludedReferences.Has(string(match)) {
		return nil, false, fmt.Errorf("invalid template reference %q", string(match))
	}

	required := resourceread.ReadDeploymentV1OrDie(tmpl)

	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return nil, false, err
	} else if oidcAvailable {
		if err := c.kubeClient.AppsV1().Deployments(required.Namespace).Delete(ctx, required.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return nil, false, err
		}
		return required, true, nil
	}

	// use the following routine for things that would require special formatting/padding (yaml)
	encodedArgs := arguments.EncodeWithDelimiter(args, " \\\n  ")
	r = strings.NewReplacer(
		"${FLAGS}", encodedArgs,
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

	required.Labels["revision"] = strconv.Itoa(int(operatorStatus.LatestAvailableRevision))
	required.Spec.Template.Labels["revision"] = strconv.Itoa(int(operatorStatus.LatestAvailableRevision))

	// we watch some resources so that our deployment will redeploy without explicitly and carefully ordered resource creation
	inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferences(
		ctx,
		c.kubeClient,
		resourcehash.NewObjectRef().ForSecret().InNamespace(c.targetNamespace).Named("etcd-client"),
		resourcehash.NewObjectRef().ForConfigMap().InNamespace(c.targetNamespace).Named("etcd-serving-ca"),
		resourcehash.NewObjectRef().ForConfigMap().InNamespace(c.targetNamespace).Named("trusted-ca-bundle"),
	)
	if err != nil {
		return nil, false, fmt.Errorf("invalid dependency reference: %q", err)
	}

	for k, v := range inputHashes {
		annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
		required.Annotations[annotationKey] = v
		if required.Spec.Template.Annotations == nil {
			required.Spec.Template.Annotations = map[string]string{}
		}
		required.Spec.Template.Annotations[annotationKey] = v
	}

	err = c.ensureAtMostOnePodPerNode(&required.Spec, "oauth-apiserver")
	if err != nil {
		return nil, false, fmt.Errorf("unable to ensure at most one pod per node: %v", err)
	}

	// Set the replica count to the number of master nodes.
	masterNodeCount, err := c.countNodes(required.Spec.Template.Spec.NodeSelector)
	if err != nil {
		return nil, false, fmt.Errorf("failed to determine number of master nodes: %v", err)
	}
	required.Spec.Replicas = masterNodeCount

	deployment, _, err := resourceapply.ApplyDeployment(ctx, c.kubeClient.AppsV1(), eventRecorder, required, resourcemerge.ExpectedDeploymentGeneration(required, operatorStatus.Generations))
	return deployment, false, err
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

// GetAPIServerArgumentsRaw
func GetAPIServerArgumentsRaw(authOperatorSpec operatorv1.OperatorSpec) (map[string]interface{}, error) {
	unstructuredCfg, err := common.UnstructuredConfigFrom(
		authOperatorSpec.ObservedConfig.Raw,
		oauthapiconfigobservercontroller.OAuthAPIServerConfigPrefix,
	)
	if err != nil {
		return nil, err
	}

	unstructuredUnsupportedCfg, err := common.UnstructuredConfigFrom(
		authOperatorSpec.UnsupportedConfigOverrides.Raw,
		oauthapiconfigobservercontroller.OAuthAPIServerConfigPrefix,
	)
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

	cfgUnstructured := new(struct {
		APIServerArguments map[string]interface{} `json:"apiServerArguments"`
	})
	if err := json.Unmarshal(unstructuredMergedCfg, cfgUnstructured); err != nil {
		return nil, err
	}

	return cfgUnstructured.APIServerArguments, nil
}
