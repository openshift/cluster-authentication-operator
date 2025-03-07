package common

import (
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

// ExternalOIDCConfigAvailable checks the kubeapiservers/cluster resource for KAS pod
// rollout status; it returns true if auth type is OIDC, all KAS pods are currently on a revision
// that includes the structured auth-config ConfigMap, and the KAS args include the respective
// arg that enables usage of the structured auth-config. It returns false otherwise.
func ExternalOIDCConfigAvailable(authLister configv1listers.AuthenticationLister, kasLister operatorv1listers.KubeAPIServerLister, cmLister corelistersv1.ConfigMapLister) (bool, error) {
	auth, err := authLister.Get("cluster")
	if err != nil {
		return false, err
	}

	if auth.Spec.Type != configv1.AuthenticationTypeOIDC {
		return false, nil
	}

	kas, err := kasLister.Get("cluster")
	if err != nil {
		return false, err
	}

	observedRevisions := sets.New[int32]()
	for _, nodeStatus := range kas.Status.NodeStatuses {
		observedRevisions.Insert(nodeStatus.CurrentRevision)
	}

	if observedRevisions.Len() == 0 {
		return false, nil
	}

	for _, revision := range observedRevisions.UnsortedList() {
		// ensure every observed revision includes an auth-config revisioned configmap
		_, err := cmLister.ConfigMaps("openshift-kube-apiserver").Get(fmt.Sprintf("auth-config-%d", revision))
		if errors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}

		// every observed revision includes a copy of the KAS config configmap
		cm, err := cmLister.ConfigMaps("openshift-kube-apiserver").Get(fmt.Sprintf("config-%d", revision))
		if err != nil {
			return false, err
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
