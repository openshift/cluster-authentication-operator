package configobservercontroller

import (
	"context"
	"net/http"
	"testing"
	"time"

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

	mustGatherRoundTripper, err := manifestclient.NewRoundTripper("/home/deads/Downloads/must-gather-01")
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{
		Transport: mustGatherRoundTripper,
	}

	kubeClient, err := kubernetes.NewForConfigAndClient(&rest.Config{}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	configClient, err := configclient.NewForConfigAndClient(&rest.Config{}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	operatorClient, dynamicInformers, err := genericoperatorclient.NewClusterScopedOperatorClientWithClient(&rest.Config{}, httpClient, operatorv1.GroupVersion.WithResource("authentications"))
	if err != nil {
		t.Fatal(err)
	}
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

}
