package deployment

import (
	"context"
	"fmt"
	"os"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	routeinformers "github.com/openshift/client-go/route/informers/externalversions"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"
)

var _ workload.Delegate = &oauthServerDeploymentSyncer{}

// nodeCountFunction a function to return count of nodes
type nodeCountFunc func(nodeSelector map[string]string) (*int32, error)

// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
// one pod of a given replicaset from landing on a node.
type ensureAtMostOnePodPerNodeFunc func(spec *appsv1.DeploymentSpec, componentName string) error

type oauthServerDeploymentSyncer struct {
	operatorClient v1helpers.OperatorClient

	// countNodes a function to return count of nodes on which the workload will be installed
	countNodes nodeCountFunc
	// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
	// one pod of a given replicaset from landing on a node.
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc

	deployments appsv1client.DeploymentsGetter

	configMapLister corev1listers.ConfigMapLister
	secretLister    corev1listers.SecretLister
	podsLister      corev1listers.PodLister
	proxyLister     configv1listers.ProxyLister
	routeLister     routev1listers.RouteLister

	bootstrapUserDataGetter    bootstrap.BootstrapUserDataGetter
	bootstrapUserChangeRollOut bool
}

func NewOAuthServerWorkloadController(
	operatorClient v1helpers.OperatorClient,
	countNodes nodeCountFunc,
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc,
	kubeClient kubernetes.Interface,
	nodeInformer coreinformers.NodeInformer,
	openshiftClusterConfigClient configv1client.ClusterOperatorInterface,
	configInformers configinformer.SharedInformerFactory,
	routeInformersForTargetNamespace routeinformers.SharedInformerFactory,
	bootstrapUserDataGetter bootstrap.BootstrapUserDataGetter,
	eventsRecorder events.Recorder,
	versionRecorder status.VersionGetter,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
) factory.Controller {
	targetNS := "openshift-authentication"

	oauthDeploymentSyncer := &oauthServerDeploymentSyncer{
		operatorClient: operatorClient,

		countNodes:                countNodes,
		ensureAtMostOnePodPerNode: ensureAtMostOnePodPerNode,

		deployments: kubeClient.AppsV1(),

		configMapLister: kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		secretLister:    kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		podsLister:      kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		proxyLister:     configInformers.Config().V1().Proxies().Lister(),
		routeLister:     routeInformersForTargetNamespace.Route().V1().Routes().Lister(),

		bootstrapUserDataGetter: bootstrapUserDataGetter,
	}

	if userExists, err := oauthDeploymentSyncer.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("unable to determine the state of bootstrap user: %v", err)
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = true
	} else {
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = userExists
	}

	return workload.NewController(
		"OAuthServer",
		"cluster-authentication-operator",
		targetNS,
		os.Getenv("OPERAND_OAUTH_SERVER_IMAGE_VERSION"),
		"",
		"OAuthServer",
		operatorClient,
		kubeClient,
		kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		[]factory.Informer{
			configInformers.Config().V1().Ingresses().Informer(),
			configInformers.Config().V1().Proxies().Informer(),
			nodeInformer.Informer(),
		},
		[]factory.Informer{
			kubeInformersForTargetNamespace.Apps().V1().Deployments().Informer(),
			kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Namespaces().Informer(),
			routeInformersForTargetNamespace.Route().V1().Routes().Informer(),
		},
		oauthDeploymentSyncer,
		openshiftClusterConfigClient,
		eventsRecorder,
		versionRecorder,
	)
}

func (c *oauthServerDeploymentSyncer) PreconditionFulfilled(_ context.Context) (bool, error) {
	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return false, fmt.Errorf("waiting for the oauth-openshift route to appear: %w", err)
	}

	if _, _, err := routeapihelpers.IngressURI(route, ""); err != nil {
		return false, fmt.Errorf("waiting for the oauth-openshift route to contain an admitted ingress: %w", err)
	}

	return true, nil
}

func (c *oauthServerDeploymentSyncer) WorkloadDeleted(_ context.Context) (bool, string, error) {
	return false, "", nil
}

func (c *oauthServerDeploymentSyncer) Sync(ctx context.Context, syncContext factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	errs := []error{}

	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return nil, false, append(errs, err)
	}

	proxyConfig, err := c.getProxyConfig()
	if err != nil {
		return nil, false, append(errs, err)
	}

	// resourceVersions serves to store versions of config resources so that we
	// can redeploy our payload should either change. We only omit the operator
	// config version, it would both cause redeploy loops (status updates cause
	// version change) and the relevant changes (logLevel, unsupportedConfigOverrides)
	// will cause a redeploy anyway
	// TODO move this hash from deployment meta to operatorConfig.status.generations.[...].hash
	resourceVersions := []string{}

	if len(proxyConfig.Name) > 0 {
		resourceVersions = append(resourceVersions, "proxy:"+proxyConfig.Name+":"+proxyConfig.ResourceVersion)
	}

	configResourceVersions, err := c.getConfigResourceVersions()
	if err != nil {
		return nil, false, append(errs, err)
	}

	resourceVersions = append(resourceVersions, configResourceVersions...)

	// Determine whether the bootstrap user has been deleted so that
	// detail can be used in computing the deployment.
	if c.bootstrapUserChangeRollOut {
		if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
			klog.Warningf("unable to determine the state of bootstrap user: %v", err)
		} else {
			c.bootstrapUserChangeRollOut = userExists
		}
	}

	// deployment, have RV of all resources
	expectedDeployment, err := getOAuthServerDeployment(operatorSpec, proxyConfig, c.bootstrapUserChangeRollOut, resourceVersions...)
	if err != nil {
		return nil, false, append(errs, err)
	}

	if _, err := c.secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-custom-router-certs"); err == nil {
		expectedDeployment.Spec.Template.Spec.Volumes = append(expectedDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "v4-0-config-system-custom-router-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "v4-0-config-system-custom-router-certs",
				},
			},
		})
		expectedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(expectedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "v4-0-config-system-custom-router-certs",
			ReadOnly:  true,
			MountPath: "/var/config/system/secrets/v4-0-config-system-custom-router-certs",
		})
	}

	err = c.ensureAtMostOnePodPerNode(&expectedDeployment.Spec, "oauth-openshift")
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("unable to ensure at most one pod per node: %v", err))
	}

	// Set the replica count to the number of master nodes.
	masterNodeCount, err := c.countNodes(expectedDeployment.Spec.Template.Spec.NodeSelector)
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("failed to determine number of master nodes: %v", err))
	}
	expectedDeployment.Spec.Replicas = masterNodeCount

	deployment, _, err := resourceapply.ApplyDeployment(ctx, c.deployments,
		syncContext.Recorder(),
		expectedDeployment,
		resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorStatus.Generations),
	)
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("applying deployment of the integrated OAuth server failed: %w", err))
	}

	return deployment, true, errs
}

func (c *oauthServerDeploymentSyncer) getProxyConfig() (*configv1.Proxy, error) {
	proxyConfig, err := c.proxyLister.Get("cluster")
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(4).Infof("No proxy configuration found, defaulting to empty")
			return &configv1.Proxy{}, nil
		}
		return nil, fmt.Errorf("unable to get cluster proxy configuration: %v", err)
	}
	return proxyConfig, nil
}

func (c *oauthServerDeploymentSyncer) getConfigResourceVersions() ([]string, error) {
	var configRVs []string

	configMaps, err := c.configMapLister.ConfigMaps("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list configmaps in %q namespace: %v", "openshift-authentication", err)
	}
	for _, cm := range configMaps {
		if strings.HasPrefix(cm.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.Name+":"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secretLister.Secrets("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list secrets in %q namespace: %v", "openshift-authentication", err)
	}
	for _, secret := range secrets {
		if strings.HasPrefix(secret.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.Name+":"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}
