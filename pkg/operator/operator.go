package operator

import (
	"bytes"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers/core/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/controller"
	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/operator"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

const (
	targetNamespaceName                  = "kube-system"
	targetConfigMap                      = "cluster-config-v1"
	oldTargetKubeAPIServerOperatorConfig = "instance"
	targetKubeAPIServerOperatorConfig    = "cluster"
)

type osinOperator struct {
	configMap                      coreclientv1.ConfigMapsGetter
	oldKubeAPIServerOperatorClient dynamic.ResourceInterface
	kubeAPIServerOperatorClient    dynamic.ResourceInterface
}

func NewOsinOperator(cmi v1.ConfigMapInformer, cm coreclientv1.ConfigMapsGetter,
	oldOperatorConfigInformer controller.InformerGetter, oldKubeAPIServerOperatorClient dynamic.ResourceInterface,
	kubeAPIServerOperatorConfigInformer controller.InformerGetter, kubeAPIServerOperatorClient dynamic.ResourceInterface) operator.Runner {
	c := &osinOperator{
		configMap:                      cm,
		oldKubeAPIServerOperatorClient: oldKubeAPIServerOperatorClient,
		kubeAPIServerOperatorClient:    kubeAPIServerOperatorClient,
	}

	return operator.New("OsinOperator", c,
		operator.WithInformer(cmi, operator.FilterByNames(targetConfigMap)),
		operator.WithInformer(oldOperatorConfigInformer, operator.FilterByNames(oldTargetKubeAPIServerOperatorConfig, targetKubeAPIServerOperatorConfig), controller.WithNoSync()),
		operator.WithInformer(kubeAPIServerOperatorConfigInformer, operator.FilterByNames(oldTargetKubeAPIServerOperatorConfig, targetKubeAPIServerOperatorConfig), controller.WithNoSync()),
	)
}

func (c osinOperator) Key() (metav1.Object, error) {
	return c.configMap.ConfigMaps(targetNamespaceName).Get(targetConfigMap, metav1.GetOptions{})
}

func (c osinOperator) Sync(obj metav1.Object) error {
	configMap := obj.(*corev1.ConfigMap)

	installConfig := configMap.Data["install-config"]
	if len(installConfig) == 0 {
		return fmt.Errorf("no data: %#v", configMap)
	}
	installConfigJSON, err := yaml.ToJSON([]byte(installConfig))
	if err != nil {
		return err
	}
	ic := &InstallConfig{}
	if err := json.Unmarshal(installConfigJSON, ic); err != nil {
		return err
	}

	// try all the potential names and resources to update.  Eventually we'll be done with the old
	updateErr := updateKubeAPIServer(c.oldKubeAPIServerOperatorClient, oldTargetKubeAPIServerOperatorConfig, ic)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.kubeAPIServerOperatorClient, oldTargetKubeAPIServerOperatorConfig, ic)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.oldKubeAPIServerOperatorClient, targetKubeAPIServerOperatorConfig, ic)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.kubeAPIServerOperatorClient, targetKubeAPIServerOperatorConfig, ic)
	if updateErr == nil {
		return nil
	}

	return updateErr
}

func updateKubeAPIServer(kubeAPIServerOperatorClient dynamic.ResourceInterface, name string, ic *InstallConfig) error {
	apiServerOperatorConfig, err := kubeAPIServerOperatorClient.Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	apiServerOperatorConfigBytes, err := apiServerOperatorConfig.MarshalJSON()
	if err != nil {
		return err
	}

	apiURL := getAPIServerURL(ic)
	expectedOAuthConfig := map[string]interface{}{
		"spec": map[string]interface{}{
			"unsupportedConfigOverrides": map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"masterPublicURL": apiURL,
					"masterURL":       apiURL,
					"masterCA":        "/etc/kubernetes/static-pod-resources/configmaps/client-ca/ca-bundle.crt",
				},
			},
		},
	}
	expectedOAuthConfigBytes, err := json.Marshal(expectedOAuthConfig)
	if err != nil {
		return err
	}

	mergedBytes, err := resourcemerge.MergeProcessConfig(nil, apiServerOperatorConfigBytes, expectedOAuthConfigBytes)
	if err != nil {
		return err
	}
	if bytes.Equal(mergedBytes, apiServerOperatorConfigBytes) {
		return nil
	}

	out := &unstructured.Unstructured{}
	if err := out.UnmarshalJSON(mergedBytes); err != nil {
		return err
	}
	_, updateErr := kubeAPIServerOperatorClient.Update(out, metav1.UpdateOptions{})
	return updateErr
}
