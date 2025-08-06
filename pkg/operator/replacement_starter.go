package operator

import (
	"context"
	"fmt"
	"os"
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/utils/clock"

	kubemigratorclient "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/clientset"
	migrationv1alpha1informer "sigs.k8s.io/kube-storage-version-migrator/pkg/clients/informer"

	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"

	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	routeinformer "github.com/openshift/client-go/route/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/manifestclient"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
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
	apiextensionClient           apiextensionsclient.Interface
	eventRecorder                events.Recorder
	clock                        clock.PassiveClock
	featureGateAccessor          featureGateAccessorFunc

	informerFactories []libraryapplyconfiguration.SimplifiedInformerFactory
}

const componentName = "cluster-authentication-operator"

func CreateOperatorInputFromMOM(ctx context.Context, momInput libraryapplyconfiguration.ApplyConfigurationInput) (*authenticationOperatorInput, error) {
	kubeClient, err := kubernetes.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	configClient, err := configclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	operatorClient, err := operatorclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	routeClient, err := routeclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	apiregistrationv1Client, err := apiregistrationclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	migrationClient, err := kubemigratorclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}
	apiextensionClient, err := apiextensionsclient.NewForConfigAndClient(manifestclient.RecommendedRESTConfig(), momInput.MutationTrackingClient.GetHTTPClient())
	if err != nil {
		return nil, err
	}

	authenticationOperatorClient, dynamicInformers, err := genericoperatorclient.NewOperatorClientWithClient(
		momInput.Clock,
		momInput.MutationTrackingClient.GetHTTPClient(),
		operatorv1.GroupVersion.WithResource("authentications"),
		operatorv1.GroupVersion.WithKind("Authentication"),
		ExtractOperatorSpec,
		ExtractOperatorStatus,
	)
	if err != nil {
		return nil, err
	}

	//eventRecorder := events.NewKubeRecorderWithOptions(
	//	kubeClient.CoreV1().Events("openshift-authentication-operator"),
	//	events.RecommendedClusterSingletonCorrelatorOptions(),
	//	componentName,
	//	&corev1.ObjectReference{
	//		Kind:      "Deployment",
	//		Namespace: "openshift-authentication-operator",
	//		Name:      "authentication-operator",
	//	},
	//)
	// TODO figure out if we're better off using the event correlator (possible) and making a flush of some kind or if live write are better
	// but for now don't lose it.
	eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("openshift-authentication-operator"),
		componentName,
		&corev1.ObjectReference{
			Kind:      "Deployment",
			Namespace: "openshift-authentication-operator",
			Name:      "authentication-operator",
		}, momInput.Clock)

	return &authenticationOperatorInput{
		kubeClient:                   kubeClient,
		configClient:                 configClient,
		operatorClient:               operatorClient,
		routeClient:                  routeClient,
		oauthClient:                  oauthClient,
		authenticationOperatorClient: authenticationOperatorClient,
		apiregistrationv1Client:      apiregistrationv1Client,
		migrationClient:              migrationClient,
		apiextensionClient:           apiextensionClient,
		eventRecorder:                eventRecorder,
		clock:                        momInput.Clock,
		featureGateAccessor:          staticFeatureGateAccessor([]ocpconfigv1.FeatureGateName{features.FeatureGateExternalOIDC}, []ocpconfigv1.FeatureGateName{}),
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
	apiextensionsClient, err := apiextensionsclient.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return nil, err
	}

	authenticationOperatorClient, dynamicInformers, err := genericoperatorclient.NewClusterScopedOperatorClient(
		controllerContext.Clock,
		controllerContext.KubeConfig,
		operatorv1.GroupVersion.WithResource("authentications"),
		operatorv1.GroupVersion.WithKind("Authentication"),
		ExtractOperatorSpec,
		ExtractOperatorStatus,
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
		controllerContext.Clock,
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
		apiextensionClient:           apiextensionsClient,
		eventRecorder:                eventRecorder,
		clock:                        controllerContext.Clock,
		featureGateAccessor:          defaultFeatureGateAccessor,
		informerFactories: []libraryapplyconfiguration.SimplifiedInformerFactory{
			libraryapplyconfiguration.DynamicInformerFactoryAdapter(dynamicInformers), // we don't share the dynamic informers, but we only want to start when requested
		},
	}, nil
}

type authenticationOperatorInformerFactories struct {
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces
	operatorConfigInformer     configinformer.SharedInformerFactory
	operatorInformer           operatorinformer.SharedInformerFactory
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
			"openshift-kube-apiserver",
			"", // an informer for non-namespaced resources
			"kube-system",
			libgoetcd.EtcdEndpointNamespace,
		),
		operatorConfigInformer:   configinformer.NewSharedInformerFactoryWithOptions(authOperatorInput.configClient, resync),
		operatorInformer:         operatorinformer.NewSharedInformerFactory(authOperatorInput.operatorClient, 24*time.Hour),
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
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-resourceSyncer", resourceSyncer.Sync))

	configOverridesController := unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController("openshift-authentication", authOperatorInput.authenticationOperatorClient, authOperatorInput.eventRecorder)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(configOverridesController.Run))
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-configOverridesController", configOverridesController.Sync))

	logLevelController := loglevel.NewClusterOperatorLoggingController(authOperatorInput.authenticationOperatorClient, authOperatorInput.eventRecorder)
	ret.ControllerRunFns = append(ret.ControllerRunFns, libraryapplyconfiguration.AdaptRunFn(logLevelController.Run))
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, libraryapplyconfiguration.AdaptSyncFn(authOperatorInput.eventRecorder, "TODO-logLevelController", logLevelController.Sync))

	oauthRunOnceFns, oauthRunFns, err := prepareOauthOperator(ctx, authOperatorInput, informerFactories, resourceSyncer, versionRecorder)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare oauth server: %w", err)
	}
	ret.ControllerRunFns = append(ret.ControllerRunFns, oauthRunFns...)
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, oauthRunOnceFns...)

	oauthAPIServerRunOnceFns, oauthAPIServerRunFns, err := prepareOauthAPIServerOperator(ctx, authOperatorInput, informerFactories, resourceSyncer, versionRecorder)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare oauth apiserver: %w", err)
	}
	ret.ControllerRunFns = append(ret.ControllerRunFns, oauthAPIServerRunFns...)
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, oauthAPIServerRunOnceFns...)

	externalOIDCRunOnceFns, externalOIDCRunFns, err := prepareExternalOIDC(ctx, authOperatorInput, informerFactories)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare external OIDC: %w", err)
	}
	ret.ControllerRunFns = append(ret.ControllerRunFns, externalOIDCRunFns...)
	ret.ControllerNamedRunOnceFns = append(ret.ControllerNamedRunOnceFns, externalOIDCRunOnceFns...)

	return ret, nil
}

type featureGateAccessorFunc func(ctx context.Context, authOperatorInput *authenticationOperatorInput, informerFactories authenticationOperatorInformerFactories) (featuregates.FeatureGate, error)

func defaultFeatureGateAccessor(ctx context.Context, authOperatorInput *authenticationOperatorInput, informerFactories authenticationOperatorInformerFactories) (featuregates.FeatureGate, error) {
	// By default, this will exit(0) if the featuregates change
	featureGateAccessor := featuregates.NewFeatureGateAccess(
		status.VersionForOperatorFromEnv(), "0.0.1-snapshot",
		informerFactories.operatorConfigInformer.Config().V1().ClusterVersions(),
		informerFactories.operatorConfigInformer.Config().V1().FeatureGates(),
		authOperatorInput.eventRecorder,
	)
	go featureGateAccessor.Run(ctx)
	go informerFactories.operatorConfigInformer.Start(ctx.Done())

	var featureGates featuregates.FeatureGate
	select {
	case <-featureGateAccessor.InitialFeatureGatesObserved():
		featureGates, _ = featureGateAccessor.CurrentFeatureGates()
	case <-time.After(1 * time.Minute):
		return nil, fmt.Errorf("timed out waiting for FeatureGate detection")
	}
	return featureGates, nil
}

// staticFeatureGateAccessor is primarly used during testing to statically enable or disable features.
func staticFeatureGateAccessor(enabled, disabled []ocpconfigv1.FeatureGateName) featureGateAccessorFunc {
	return func(_ context.Context, _ *authenticationOperatorInput, _ authenticationOperatorInformerFactories) (featuregates.FeatureGate, error) {
		return featuregates.NewFeatureGate(enabled, disabled), nil
	}
}
