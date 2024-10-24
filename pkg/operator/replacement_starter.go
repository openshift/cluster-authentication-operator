package operator

import (
	"context"
	"fmt"
	"os"
	"time"

	kubeinformers "k8s.io/client-go/informers"

	kubemigratorclient "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/clientset"
	migrationv1alpha1informer "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/informer"

	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"

	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformers "github.com/openshift/client-go/oauth/informers/externalversions"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
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
	routeClient                  routeclient.Interface
	oauthClient                  oauthclient.Interface
	authenticationOperatorClient v1helpers.OperatorClient
	apiregistrationv1Client      apiregistrationclient.Interface
	migrationClient              kubemigratorclient.Interface
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
	routeClient, err := routeclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	apiregistrationv1Client, err := apiregistrationclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	migrationClient, err := kubemigratorclient.NewForConfigAndClient(&rest.Config{}, momInput.MutationTrackingClient.GetHTTPClient())
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
		routeClient:                  routeClient,
		oauthClient:                  oauthClient,
		authenticationOperatorClient: authenticationOperatorClient,
		apiregistrationv1Client:      apiregistrationv1Client,
		migrationClient:              migrationClient,
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
	routeClient, err := routeclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return nil, err
	}
	apiregistrationv1Client, err := apiregistrationclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return nil, err
	}
	migrationClient, err := kubemigratorclient.NewForConfig(controllerContext.KubeConfig)
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
		routeClient:                  routeClient,
		oauthClient:                  oauthClient,
		authenticationOperatorClient: authenticationOperatorClient,
		apiregistrationv1Client:      apiregistrationv1Client,
		migrationClient:              migrationClient,
		eventRecorder:                eventRecorder,
		informerFactories: []libraryapplyconfiguration.SimplifiedInformerFactory{
			libraryapplyconfiguration.DynamicInformerFactoryAdapter(dynamicInformers), // we don't share the dynamic informers, but we only want to start when requested
		},
	}, nil
}

type authenticationOperatorInformerFactories struct {
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces
	operatorConfigInformer     configinformer.SharedInformerFactory
	operatorInformer           operatorinformer.SharedInformerFactory
	oauthInformers             oauthinformers.SharedInformerFactory
	apiregistrationInformers   apiregistrationinformers.SharedInformerFactory
	migrationInformer          migrationv1alpha1informer.SharedInformerFactory
	// TODO remove
	kubeInformers kubeinformers.SharedInformerFactory

	namespacedOpenshiftAuthenticationRoutes routeinformer.SharedInformerFactory
}

func newInformerFactories(authOperatorInput *authenticationOperatorInput) authenticationOperatorInformerFactories {
	return authenticationOperatorInformerFactories{
		kubeInformersForNamespaces: v1helpers.NewKubeInformersForNamespaces(
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
		),
		operatorConfigInformer:   configinformer.NewSharedInformerFactoryWithOptions(authOperatorInput.configClient, resync),
		operatorInformer:         operatorinformer.NewSharedInformerFactory(authOperatorInput.operatorClient, 24*time.Hour),
		oauthInformers:           oauthinformers.NewSharedInformerFactory(authOperatorInput.oauthClient, resync),
		apiregistrationInformers: apiregistrationinformers.NewSharedInformerFactory(authOperatorInput.apiregistrationv1Client, 10*time.Minute),
		migrationInformer:        migrationv1alpha1informer.NewSharedInformerFactory(authOperatorInput.migrationClient, time.Minute*30),
		kubeInformers:            kubeinformers.NewSharedInformerFactory(authOperatorInput.kubeClient, resync),

		namespacedOpenshiftAuthenticationRoutes: routeinformer.NewSharedInformerFactoryWithOptions(authOperatorInput.routeClient, resync,
			routeinformer.WithNamespace("openshift-authentication"),
			routeinformer.WithTweakListOptions(singleNameListOptions("oauth-openshift")),
		),
	}
}

func (a authenticationOperatorInformerFactories) simplifiedInformerFactories() []libraryapplyconfiguration.SimplifiedInformerFactory {
	return []libraryapplyconfiguration.SimplifiedInformerFactory{
		libraryapplyconfiguration.GeneratedNamespacedInformerFactoryAdapter(a.kubeInformersForNamespaces),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.operatorInformer),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.operatorConfigInformer),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.oauthInformers),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.apiregistrationInformers),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.migrationInformer),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.kubeInformers),
		libraryapplyconfiguration.GeneratedInformerFactoryAdapter(a.namespacedOpenshiftAuthenticationRoutes),
	}
}

func CreateOperatorStarter(ctx context.Context, authOperatorInput *authenticationOperatorInput) (libraryapplyconfiguration.OperatorStarter, error) {
	ret := &libraryapplyconfiguration.SimpleOperatorStarter{
		Informers: append([]libraryapplyconfiguration.SimplifiedInformerFactory{}, authOperatorInput.informerFactories...),
	}

	informerFactories := newInformerFactories(authOperatorInput)
	ret.Informers = append(ret.Informers, informerFactories.simplifiedInformerFactories()...)

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
		informerFactories.kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(authOperatorInput.kubeClient.CoreV1(), informerFactories.kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(authOperatorInput.kubeClient.CoreV1(), informerFactories.kubeInformersForNamespaces),
		authOperatorInput.eventRecorder,
	)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(resourceSyncer.Run))
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, resourceSyncer.Sync))

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController("oauth-server", authOperatorInput.authenticationOperatorClient, authOperatorInput.eventRecorder)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(configOverridesController.Run))
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, configOverridesController.Sync))

	logLevelController := loglevel.NewClusterOperatorLoggingController(authOperatorInput.authenticationOperatorClient, authOperatorInput.eventRecorder)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(logLevelController.Run))
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, logLevelController.Sync))

	oauthRunOnceFns, oauthRunFns, err := prepareOauthOperator(ctx, authOperatorInput, informerFactories, resourceSyncer, versionRecorder)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare oauth server: %w", err)
	}
	ret.ControllerRunFns = append(ret.ControllerRunFns, oauthRunFns...)
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, oauthRunOnceFns...)

	oauthAPIServerRunOnceFns, oauthAPIServerRunFns, err := prepareOauthAPIServerOperator(ctx, authOperatorInput, informerFactories, resourceSyncer, versionRecorder)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare oauth server: %w", err)
	}
	ret.ControllerRunFns = append(ret.ControllerRunFns, oauthAPIServerRunFns...)
	ret.ControllerRunOnceFns = append(ret.ControllerRunOnceFns, oauthAPIServerRunOnceFns...)

	return ret, nil
}
