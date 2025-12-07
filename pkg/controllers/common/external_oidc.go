package common

import (
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

type AuthConfigChecker struct {
	authenticationsInformer        cache.SharedIndexInformer
	kubeAPIServersInformer         cache.SharedIndexInformer
	kasNamespaceConfigMapsInformer cache.SharedIndexInformer

	authLister         configv1listers.AuthenticationLister
	kasLister          operatorv1listers.KubeAPIServerLister
	kasConfigMapLister corelistersv1.ConfigMapLister
}

func NewAuthConfigChecker(authentications configv1informers.AuthenticationInformer, kubeapiservers operatorv1informers.KubeAPIServerInformer, configmaps corev1informers.ConfigMapInformer) AuthConfigChecker {
	return AuthConfigChecker{
		authenticationsInformer:        authentications.Informer(),
		kubeAPIServersInformer:         kubeapiservers.Informer(),
		kasNamespaceConfigMapsInformer: configmaps.Informer(),
		authLister:                     authentications.Lister(),
		kasLister:                      kubeapiservers.Lister(),
		kasConfigMapLister:             configmaps.Lister(),
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
		return false, fmt.Errorf("AuthConfigChecker configmaps informer has not synced yet")
	}

	if auth, err := c.authLister.Get("cluster"); err != nil {
		return false, fmt.Errorf("getting authentications.config.openshift.io/cluster: %v", err)
	} else if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		return false, nil
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
