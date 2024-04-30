package configobservercontroller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/manifestclient"
	libgoetcd "github.com/openshift/library-go/pkg/operator/configobserver/etcd"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestApplyConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mutationTrackingHTTPClient := manifestclient.NewHTTPClient("/home/deads/Downloads/must-gather-01")

	kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, mutationTrackingHTTPClient.GetHTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, mutationTrackingHTTPClient.GetHTTPClient())
	if err != nil {
		t.Fatal(err)
	}

	operatorClient, dynamicInformers, err := genericoperatorclient.NewOperatorClientWithClient(
		mutationTrackingHTTPClient.GetHTTPClient(),
		operatorv1.GroupVersion.WithResource("authentications"),
		operatorv1.GroupVersion.WithKind("Authentication"),
		extractOperatorSpec,
		extractOperatorStatus,
	)

	eventRecorder := events.NewLoggingEventRecorder("cluster-authentication-operator")

	configInformers := configinformer.NewSharedInformerFactoryWithOptions(configClient, 0)
	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
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
	resourceSyncer := resourcesynccontroller.NewResourceSyncController(
		"oauth-server",
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		eventRecorder,
	)

	clusterVersion, err := configClient.ConfigV1().ClusterVersions().Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	enabledClusterCapabilities := sets.NewString()
	for _, v := range clusterVersion.Status.Capabilities.EnabledCapabilities {
		enabledClusterCapabilities.Insert(string(v))
	}

	configObserver := NewConfigObserver(
		operatorClient,
		kubeInformersForNamespaces,
		configInformers,
		resourceSyncer,
		enabledClusterCapabilities,
		eventRecorder,
	)
	configInformers.Start(ctx.Done())
	kubeInformersForNamespaces.Start(ctx.Done())
	dynamicInformers.Start(ctx.Done())

	// wait for cache sync (nearly instant from disk)
	time.Sleep(1 * time.Second)

	syncCtx := factory.NewSyncContext("test-sync-context", eventRecorder)
	syncErr := configObserver.Sync(ctx, syncCtx)
	if syncErr != nil {
		t.Fatal(syncErr)
	}

	mutations := mutationTrackingHTTPClient.GetMutations()
	t.Fatal(spew.Sdump(mutations))
}

func extractOperatorSpec(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	castObj := &operatorv1.Authentication{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to Authentication: %w", err)
	}
	ret, err := applyoperatorv1.ExtractAuthentication(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}
	if ret.Spec == nil {
		return nil, nil
	}
	return &ret.Spec.OperatorSpecApplyConfiguration, nil
}

func extractOperatorStatus(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	castObj := &operatorv1.Authentication{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to Authentication: %w", err)
	}
	ret, err := applyoperatorv1.ExtractAuthenticationStatus(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}

	if ret.Status == nil {
		return nil, nil
	}
	return &ret.Status.OperatorStatusApplyConfiguration, nil
}
