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
	targetNamespaceName              = "kube-system"
	targetConfigMap                  = "cluster-config-v1"
	targtKubeAPIServerOperatorConfig = "instance"
)

type osinOperator struct {
	configMap                   coreclientv1.ConfigMapsGetter
	kubeAPIServerOperatorConfig dynamic.ResourceInterface
}

func NewOsinOperator(cmi v1.ConfigMapInformer, cm coreclientv1.ConfigMapsGetter, operatorConfigInformer controller.InformerGetter, operatorConfig dynamic.ResourceInterface) operator.Runner {
	c := &osinOperator{
		configMap:                   cm,
		kubeAPIServerOperatorConfig: operatorConfig,
	}

	return operator.New("OsinOperator", c,
		operator.WithInformer(cmi, operator.FilterByNames(targetConfigMap)),
		operator.WithInformer(operatorConfigInformer, operator.FilterByNames(targtKubeAPIServerOperatorConfig)),
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

	apiServerOperatorConfig, err := c.kubeAPIServerOperatorConfig.Get(targtKubeAPIServerOperatorConfig, metav1.GetOptions{})
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
	_, updateErr := c.kubeAPIServerOperatorConfig.Update(out)
	return updateErr
}
