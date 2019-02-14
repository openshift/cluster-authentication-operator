package operator

import (
	"bytes"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/controller"
	"github.com/openshift/cluster-authentication-operator/pkg/boilerplate/operator"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

const (
	oldTargetKubeAPIServerOperatorConfig = "instance"
	targetKubeAPIServerOperatorConfig    = "cluster"
	targetInfratructureConfig            = "cluster"
)

type osinOperator struct {
	oldKubeAPIServerOperatorClient dynamic.ResourceInterface
	kubeAPIServerOperatorClient    dynamic.ResourceInterface
	infrastructureConfigClient     dynamic.ResourceInterface
}

func NewOsinOperator(
	oldOperatorConfigInformer controller.InformerGetter, oldKubeAPIServerOperatorClient dynamic.ResourceInterface,
	kubeAPIServerOperatorConfigInformer controller.InformerGetter, kubeAPIServerOperatorClient dynamic.ResourceInterface,
	infrastructureConfigInformer controller.InformerGetter, infrastructureConfigClient dynamic.ResourceInterface) operator.Runner {
	c := &osinOperator{
		oldKubeAPIServerOperatorClient: oldKubeAPIServerOperatorClient,
		kubeAPIServerOperatorClient:    kubeAPIServerOperatorClient,
		infrastructureConfigClient:     infrastructureConfigClient,
	}

	return operator.New("OsinOperator", c,
		operator.WithInformer(oldOperatorConfigInformer, operator.FilterByNames(oldTargetKubeAPIServerOperatorConfig, targetKubeAPIServerOperatorConfig), controller.WithNoSync()),
		operator.WithInformer(kubeAPIServerOperatorConfigInformer, operator.FilterByNames(oldTargetKubeAPIServerOperatorConfig, targetKubeAPIServerOperatorConfig), controller.WithNoSync()),
		operator.WithInformer(infrastructureConfigInformer, operator.FilterByNames(targetInfratructureConfig), controller.WithNoSync()),
	)
}

func (c osinOperator) Key() (metav1.Object, error) {
	return c.infrastructureConfigClient.Get(targetInfratructureConfig, metav1.GetOptions{})
}

func (c osinOperator) Sync(obj metav1.Object) error {
	infra := obj.(*unstructured.Unstructured)
	// https://github.com/openshift/api/blob/ea5d05408a95a765d44b5a4b31561b530f0b1f4c/config/v1/types_infrastructure.go#L47
	apiURL, ok, err := unstructured.NestedString(infra.Object, "status", "apiServerURL")
	if err != nil {
		return err
	}
	if !ok || apiURL == "" {
		return fmt.Errorf("apiServerURL field not found")
	}

	// try all the potential names and resources to update.  Eventually we'll be done with the old
	updateErr := updateKubeAPIServer(c.oldKubeAPIServerOperatorClient, oldTargetKubeAPIServerOperatorConfig, apiURL)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.kubeAPIServerOperatorClient, oldTargetKubeAPIServerOperatorConfig, apiURL)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.oldKubeAPIServerOperatorClient, targetKubeAPIServerOperatorConfig, apiURL)
	if updateErr == nil {
		return nil
	}

	updateErr = updateKubeAPIServer(c.kubeAPIServerOperatorClient, targetKubeAPIServerOperatorConfig, apiURL)
	if updateErr == nil {
		return nil
	}

	return updateErr
}

func updateKubeAPIServer(kubeAPIServerOperatorClient dynamic.ResourceInterface, name, apiURL string) error {
	apiServerOperatorConfig, err := kubeAPIServerOperatorClient.Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	apiServerOperatorConfigBytes, err := apiServerOperatorConfig.MarshalJSON()
	if err != nil {
		return err
	}

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
