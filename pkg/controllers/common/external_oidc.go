package common

import (
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

type AuthConfigChecker struct {
	authenticationsInformer         cache.SharedIndexInformer
	kubeAPIServersInformer          cache.SharedIndexInformer
	kasNamespaceConfigMapsInformer  cache.SharedIndexInformer
	oaasNamespaceConfigMapsInformer cache.SharedIndexInformer

	authLister          configv1listers.AuthenticationLister
	kasLister           operatorv1listers.KubeAPIServerLister
	kasConfigMapLister  corelistersv1.ConfigMapLister
	oaasConfigMapLister corelistersv1.ConfigMapLister

	featureGateAccessor featuregates.FeatureGateAccess
}

func NewAuthConfigChecker(authentications configv1informers.AuthenticationInformer, kubeapiservers operatorv1informers.KubeAPIServerInformer, kasConfigMaps, oaasConfigMaps corev1informers.ConfigMapInformer, featureGateAccessor featuregates.FeatureGateAccess) AuthConfigChecker {
	return AuthConfigChecker{
		authenticationsInformer:         authentications.Informer(),
		kubeAPIServersInformer:          kubeapiservers.Informer(),
		kasNamespaceConfigMapsInformer:  kasConfigMaps.Informer(),
		oaasNamespaceConfigMapsInformer: oaasConfigMaps.Informer(),
		authLister:                      authentications.Lister(),
		kasLister:                       kubeapiservers.Lister(),
		kasConfigMapLister:              kasConfigMaps.Lister(),
		oaasConfigMapLister:             oaasConfigMaps.Lister(),
		featureGateAccessor:             featureGateAccessor,
	}
}

func (c *AuthConfigChecker) AuthConfig() (*configv1.Authentication, error) {
	return c.authLister.Get("cluster")
}

func AuthConfigCheckerInformers[T factory.Informer](c *AuthConfigChecker) []T {
	return []T{
		c.authenticationsInformer.(T),
		c.kubeAPIServersInformer.(T),
		c.kasNamespaceConfigMapsInformer.(T),
		c.oaasNamespaceConfigMapsInformer.(T),
	}
}

// OIDCAvailable checks the kubeapiservers/cluster resource for KAS pod
// rollout status; it returns true if auth type is OIDC, all KAS pods are currently on a revision
// that includes the structured auth-config ConfigMap, and the KAS args include the respective
// arg that enables usage of the structured auth-config. It returns false otherwise.
func (c *AuthConfigChecker) OIDCAvailable() (bool, error) {
	if !c.authenticationsInformer.HasSynced() {
		return false, fmt.Errorf("AuthConfigChecker authentications informer has not synced yet")
	}

	if !c.kubeAPIServersInformer.HasSynced() {
		return false, fmt.Errorf("AuthConfigChecker kubeapiservers informer has not synced yet")
	}

	if !c.kasNamespaceConfigMapsInformer.HasSynced() {
		return false, fmt.Errorf("AuthConfigChecker kube-apiserver namespace configmaps informer has not synced yet")
	}

	if !c.oaasNamespaceConfigMapsInformer.HasSynced() {
		return false, fmt.Errorf("AuthConfigChecker oauth-apiserver namespace configmaps informer has not synced yet")
	}

	if !c.featureGateAccessor.AreInitialFeatureGatesObserved() {
		return false, fmt.Errorf("AuthConfigChecker initial feature gates not yet observed")
	}

	featureGates, err := c.featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return false, fmt.Errorf("AuthConfigChecker getting current feature gates: %w", err)
	}

	if auth, err := c.authLister.Get("cluster"); err != nil {
		return false, fmt.Errorf("getting authentications.config.openshift.io/cluster: %v", err)
	} else if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		return false, nil
	}

	// If the ExternalOIDCExternalClaimsSourcing feature gate is enabled then we are attempting to use the new
	// external oidc architecture that re-uses the oauth-apiserver as a webhook authenticator
	// with a new mode of operation. Because of this shift back to using the oauth-apiserver, it is
	// safe to assume that if the authentications/cluster resource has its spec.type set to OIDC
	// that OIDC is "available" as we no longer have to actually wait for a kube-apiserver revision rollout
	// to have completed prior to switching to the external OIDC operational mode.
	// The only thing we need to ensure is that there is _some_ configuration that has been successfully
	// synced to the openshift-oauth-apiserver namespace before attempting to rollout any new configurations.
	// Doing so ensures that any errors encountered during the generation of the authentication configuration
	// file doesn't cause the entirety of our authentication stack from falling over.
	if featureGates.Enabled(features.FeatureGateExternalOIDCExternalClaimsSourcing) {
		cm, err := c.oaasConfigMapLister.ConfigMaps("openshift-oauth-apiserver").Get("auth-config")
		if errors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("getting configmap openshift-oauth-apiserver/auth-config: %w", err)
		}

		if _, ok := cm.Data["auth-config.json"]; !ok {
			return false, fmt.Errorf("configmap openshift-oauth-apiserver/auth-config does not contain auth-config.json key")
		}

		return true, nil
	}

	kas, err := c.kasLister.Get("cluster")
	if err != nil {
		return false, fmt.Errorf("getting kubeapiservers.operator.openshift.io/cluster: %v", err)
	}

	if len(kas.Status.NodeStatuses) == 0 {
		return false, fmt.Errorf("determining observed revisions in kubeapiservers.operator.openshift.io/cluster; no node statuses found")
	}

	observedRevisions := sets.New[int32]()
	for _, nodeStatus := range kas.Status.NodeStatuses {
		if nodeStatus.CurrentRevision <= 0 {
			return false, fmt.Errorf("determining observed revisions in kubeapiservers.operator.openshift.io/cluster; some nodes do not have a valid CurrentRevision")
		}
		observedRevisions.Insert(nodeStatus.CurrentRevision)
	}

	for _, revision := range observedRevisions.UnsortedList() {
		// ensure every observed revision includes an auth-config revisioned configmap
		_, err := c.kasConfigMapLister.ConfigMaps("openshift-kube-apiserver").Get(fmt.Sprintf("auth-config-%d", revision))
		if errors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("getting configmap openshift-kube-apiserver/auth-config-%d: %v", revision, err)
		}

		// every observed revision includes a copy of the KAS config configmap
		cm, err := c.kasConfigMapLister.ConfigMaps("openshift-kube-apiserver").Get(fmt.Sprintf("config-%d", revision))
		if err != nil {
			return false, fmt.Errorf("getting configmap openshift-kube-apiserver/config-%d: %v", revision, err)
		}

		// ensure the KAS config of every observed revision contains the appropriate CLI arg for OIDC
		// but not the respective ones for OAuth
		if !strings.Contains(cm.Data["config.yaml"], `"oauthMetadataFile":""`) ||
			strings.Contains(cm.Data["config.yaml"], `"authentication-token-webhook-config-file":`) ||
			!strings.Contains(cm.Data["config.yaml"], `"authentication-config":["/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"]`) {
			return false, nil
		}
	}

	return true, nil
}
