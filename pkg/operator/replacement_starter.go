package operator

import (
	"context"
	"os"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/multi-operator-manager/pkg/library/libraryapplyconfiguration"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
)

type authenticationOperatorInput struct {
	kubeClient                   kubernetes.Interface
	configClient                 configclient.Interface
	operatorClient               operatorclient.Interface
	authenticationOperatorClient v1helpers.OperatorClient
	eventRecorder                events.Recorder

	informerFactories []libraryapplyconfiguration.SimplifiedInformerFactory
}

const componentName = "cluster-authentication-operator"

func CreateOperatorInputFromMOM(ctx context.Context, momInput libraryapplyconfiguration.ApplyConfigurationInput) (*authenticationOperatorInput, error) {
	kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}

	configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}

	operatorClient, err := operatorclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}

	authenticationOperatorClient, dynamicInformers, err := genericoperatorclient.NewOperatorClientWithClient(
		momInput.Clock,
		momInput.MutationTrackingClient.GetHTTPClient(),
		operatorv1.GroupVersion.WithResource("authentications"),
		operatorv1.GroupVersion.WithKind("Authentication"),
		extractOperatorSpec,
		extractOperatorStatus,
	)
	if err != nil {
		return nil, err
	}

	eventRecorder := events.NewKubeRecorderWithOptions(
		kubeClient.CoreV1().Events("openshift-authentication-operator"),
		events.RecommendedClusterSingletonCorrelatorOptions(),
		componentName,
		&corev1.ObjectReference{
			Kind:      "Deployment",
			Namespace: "openshift-authentication-operator",
			Name:      "authentication-operator",
		},
	)

	return &authenticationOperatorInput{
		kubeClient:                   kubeClient,
		configClient:                 configClient,
		operatorClient:               operatorClient,
		authenticationOperatorClient: authenticationOperatorClient,
		eventRecorder:                eventRecorder,
		informerFactories: []libraryapplyconfiguration.SimplifiedInformerFactory{
			libraryapplyconfiguration.DynamicInformerFactoryAdapter(dynamicInformers), // we don't share the dynamic informers, but we only want to start when requested
		},
	}, nil
}

func CreateControllerInputFromControllerContext(ctx context.Context, controllerContext *controllercmd.ControllerContext) (*authenticationOperatorInput, error) {
	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return nil, err
	}

	configClient, err := configclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return nil, err
	}

	operatorClient, err := operatorclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return nil, err
	}

	authenticationOperatorClient, dynamicInformers, err := genericoperatorclient.NewClusterScopedOperatorClient(
		clock.RealClock{},
		controllerContext.KubeConfig,
		operatorv1.GroupVersion.WithResource("authentications"),
		operatorv1.GroupVersion.WithKind("Authentication"),
		extractOperatorSpec,
		extractOperatorStatus,
	)
	if err != nil {
		return nil, err
	}

	eventRecorder := events.NewKubeRecorderWithOptions(
		kubeClient.CoreV1().Events("openshift-authentication-operator"),
		events.RecommendedClusterSingletonCorrelatorOptions(),
		componentName,
		&corev1.ObjectReference{
			Kind:      "Deployment",
			Namespace: "openshift-authentication-operator",
			Name:      "authentication-operator",
		},
	)

	return &authenticationOperatorInput{
		kubeClient:                   kubeClient,
		configClient:                 configClient,
		operatorClient:               operatorClient,
		authenticationOperatorClient: authenticationOperatorClient,
		eventRecorder:                eventRecorder,
		informerFactories: []libraryapplyconfiguration.SimplifiedInformerFactory{
			libraryapplyconfiguration.DynamicInformerFactoryAdapter(dynamicInformers), // we don't share the dynamic informers, but we only want to start when requested
		},
	}, nil
}

func CreateOperatorStarter(ctx context.Context, authOperatorInput *authenticationOperatorInput) (libraryapplyconfiguration.OperatorStarter, error) {
	ret := &libraryapplyconfiguration.SimpleOperatorStarter{
		Informers: append([]libraryapplyconfiguration.SimplifiedInformerFactory{}, authOperatorInput.informerFactories...),
	}
	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(
		authOperatorInput.kubeClient,
		"default",
		"openshift-authentication",
		"openshift-config",
		"openshift-config-managed",
		"openshift-oauth-apiserver",
		"openshift-authentication-operator",
		"", // an informer for non-namespaced resources
		"kube-system",
		libgoetcd.EtcdEndpointNamespace,
	)
	ret.Informers = append(ret.Informers, libraryapplyconfiguration.GeneratedNamespacedInformerFactoryAdapter(kubeInformersForNamespaces))
	// resyncs in individual controller loops for this operator are driven by a duration based trigger independent of a resource resync.
	// this allows us to resync essentially never, but reach out to external systems on a polling basis around one minute.
	operatorConfigInformers := operatorinformer.NewSharedInformerFactory(authOperatorInput.operatorClient, 24*time.Hour)
	ret.Informers = append(ret.Informers, libraryapplyconfiguration.GeneratedInformerFactoryAdapter(operatorConfigInformers))

	versionRecorder := status.NewVersionGetter()
	clusterOperator, err := authOperatorInput.configClient.ConfigV1().ClusterOperators().Get(ctx, "authentication", metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	// perform version changes to the version getter prior to tying it up in the status controller
	// via change-notification channel so that it only updates operator version in status once
	// either of the workloads synces
	for _, version := range clusterOperator.Status.Versions {
		versionRecorder.SetVersion(version.Name, version.Version)
	}
	versionRecorder.SetVersion("operator", os.Getenv("OPERATOR_IMAGE_VERSION"))

	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		"oauth-server",
		authOperatorInput.authenticationOperatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(authOperatorInput.kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(authOperatorInput.kubeClient.CoreV1(), kubeInformersForNamespaces),
		authOperatorInput.eventRecorder,
	)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(resourceSyncer.Run))
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, resourceSyncer.Sync))

	return ret, nil
}
