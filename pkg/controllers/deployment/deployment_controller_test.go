package deployment

import (
	stderrors "errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

func TestSetRollingUpdateParameters(t *testing.T) {
	testCases := []struct {
		name                   string
		controlPlaneCount      int32
		expectedMaxUnavailable int32
		expectedMaxSurge       int32
	}{
		{
			name:                   "single control plane node",
			controlPlaneCount:      1,
			expectedMaxUnavailable: 1, // max(1-1, 1) = max(0, 1) = 1
			expectedMaxSurge:       1,
		},
		{
			name:                   "two control plane nodes",
			controlPlaneCount:      2,
			expectedMaxUnavailable: 1, // max(2-1, 1) = max(1, 1) = 1
			expectedMaxSurge:       2,
		},
		{
			name:                   "three control plane nodes",
			controlPlaneCount:      3,
			expectedMaxUnavailable: 2, // max(3-1, 1) = max(2, 1) = 2
			expectedMaxSurge:       3,
		},
		{
			name:                   "four control plane nodes",
			controlPlaneCount:      4,
			expectedMaxUnavailable: 3, // max(4-1, 1) = max(3, 1) = 3
			expectedMaxSurge:       4,
		},
		{
			name:                   "five control plane nodes",
			controlPlaneCount:      5,
			expectedMaxUnavailable: 4, // max(5-1, 1) = max(4, 1) = 4
			expectedMaxSurge:       5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test deployment with rolling update strategy
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "test-namespace",
				},
				Spec: appsv1.DeploymentSpec{
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RollingUpdateDeploymentStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDeployment{
							MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
							MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
						},
					},
				},
			}

			// Call the function under test
			setRollingUpdateParameters(tc.controlPlaneCount, deployment)

			// Verify MaxUnavailable is set correctly
			if deployment.Spec.Strategy.RollingUpdate.MaxUnavailable == nil {
				t.Errorf("MaxUnavailable should not be nil")
			} else {
				actualMaxUnavailable := deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal
				if actualMaxUnavailable != tc.expectedMaxUnavailable {
					t.Errorf("Expected MaxUnavailable to be %d, got %d", tc.expectedMaxUnavailable, actualMaxUnavailable)
				}
			}

			// Verify MaxSurge is set correctly
			if deployment.Spec.Strategy.RollingUpdate.MaxSurge == nil {
				t.Errorf("MaxSurge should not be nil")
			} else {
				actualMaxSurge := deployment.Spec.Strategy.RollingUpdate.MaxSurge.IntVal
				if actualMaxSurge != tc.expectedMaxSurge {
					t.Errorf("Expected MaxSurge to be %d, got %d", tc.expectedMaxSurge, actualMaxSurge)
				}
			}

			// Verify the values are of type Int (not String)
			if deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.Type != intstr.Int {
				t.Errorf("Expected MaxUnavailable to be of type Int, got %v", deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.Type)
			}
			if deployment.Spec.Strategy.RollingUpdate.MaxSurge.Type != intstr.Int {
				t.Errorf("Expected MaxSurge to be of type Int, got %v", deployment.Spec.Strategy.RollingUpdate.MaxSurge.Type)
			}
		})
	}
}

func TestSyncComponentProxyCA(t *testing.T) {
	dest := resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: componentProxyCAConfigMapName}
	destCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: componentProxyCAConfigMapName, Namespace: "openshift-authentication"},
	}

	t.Run("trustedCA set and dest CM synced: adds volume and mount", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		require.NoError(t, indexer.Add(destCM))

		rs := &fakeResourceSyncer{}
		syncer := &oauthServerDeploymentSyncer{
			resourceSyncer:  rs,
			configMapLister: corev1listers.NewConfigMapLister(indexer),
		}

		dep := testDeployment()
		require.NoError(t, syncer.syncComponentProxyCA("my-proxy-ca", dep))

		wantSrc := resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "my-proxy-ca"}
		require.Equal(t, []configMapSyncCall{{src: wantSrc, dst: dest}}, rs.syncedConfigMaps)

		wantVolumes := []corev1.Volume{{
			Name: componentProxyCAConfigMapName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: componentProxyCAConfigMapName},
				},
			},
		}}
		if diff := cmp.Diff(wantVolumes, dep.Spec.Template.Spec.Volumes); diff != "" {
			t.Errorf("volumes mismatch (-want +got):\n%s", diff)
		}

		wantMounts := []corev1.VolumeMount{{
			Name:      componentProxyCAConfigMapName,
			ReadOnly:  true,
			MountPath: componentProxyCAMountPath,
		}}
		if diff := cmp.Diff(wantMounts, dep.Spec.Template.Spec.Containers[0].VolumeMounts); diff != "" {
			t.Errorf("volume mounts mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("trustedCA set but dest CM not yet synced: returns error", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

		rs := &fakeResourceSyncer{}
		syncer := &oauthServerDeploymentSyncer{
			resourceSyncer:  rs,
			configMapLister: corev1listers.NewConfigMapLister(indexer),
		}

		dep := testDeployment()
		err := syncer.syncComponentProxyCA("my-proxy-ca", dep)
		require.ErrorContains(t, err, "not yet synced")
		require.Empty(t, dep.Spec.Template.Spec.Volumes)
	})

	t.Run("trustedCA empty: configures RSC to delete dest CM", func(t *testing.T) {
		rs := &fakeResourceSyncer{}
		syncer := &oauthServerDeploymentSyncer{
			resourceSyncer: rs,
		}

		dep := testDeployment()
		require.NoError(t, syncer.syncComponentProxyCA("", dep))

		require.Equal(t, []configMapSyncCall{{src: resourcesynccontroller.ResourceLocation{}, dst: dest}}, rs.syncedConfigMaps)
		require.Empty(t, dep.Spec.Template.Spec.Volumes)
	})

	t.Run("SyncConfigMap error propagates", func(t *testing.T) {
		rs := &fakeResourceSyncer{err: stderrors.New("sync failed")}
		syncer := &oauthServerDeploymentSyncer{
			resourceSyncer: rs,
		}

		dep := testDeployment()
		err := syncer.syncComponentProxyCA("my-proxy-ca", dep)
		require.ErrorContains(t, err, "sync failed")
	})
}

func testDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "oauth-server"}},
				},
			},
		},
	}
}

type configMapSyncCall struct {
	src resourcesynccontroller.ResourceLocation
	dst resourcesynccontroller.ResourceLocation
}

type fakeResourceSyncer struct {
	syncedConfigMaps []configMapSyncCall
	err              error
}

func (f *fakeResourceSyncer) SyncConfigMap(dest, src resourcesynccontroller.ResourceLocation) error {
	if f.err != nil {
		return f.err
	}
	f.syncedConfigMaps = append(f.syncedConfigMaps, configMapSyncCall{src: src, dst: dest})
	return nil
}

func (f *fakeResourceSyncer) SyncSecret(_, _ resourcesynccontroller.ResourceLocation) error {
	return nil
}
