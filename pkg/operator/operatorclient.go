package operator

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"

	operatorconfigclient "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorclientinformers "github.com/openshift/client-go/operator/informers/externalversions"

	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type OperatorClient struct {
	Informers operatorclientinformers.SharedInformerFactory
	Client    operatorconfigclient.AuthenticationsGetter
}

var _ v1helpers.OperatorClient = &OperatorClient{}

// TODO: Implement this
func (c OperatorClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c OperatorClient) Informer() cache.SharedIndexInformer {
	return c.Informers.Operator().V1().Authentications().Informer()
}

func (c OperatorClient) GetOperatorState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	instance, err := c.Informers.Operator().V1().Authentications().Lister().Get("cluster")
	if err != nil {
		return nil, nil, "", err
	}

	return &instance.Spec.OperatorSpec, &instance.Status.OperatorStatus, instance.ResourceVersion, nil
}

func (c OperatorClient) UpdateOperatorSpec(ctx context.Context, resourceVersion string, spec *operatorv1.OperatorSpec) (*operatorv1.OperatorSpec, string, error) {
	original, err := c.Informers.Operator().V1().Authentications().Lister().Get("cluster")
	if err != nil {
		return nil, "", err
	}
	copy := original.DeepCopy()
	copy.ResourceVersion = resourceVersion
	copy.Spec.OperatorSpec = *spec

	ret, err := c.Client.Authentications().Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, "", err
	}

	return &ret.Spec.OperatorSpec, ret.ResourceVersion, nil
}

func (c OperatorClient) UpdateOperatorStatus(ctx context.Context, resourceVersion string, status *operatorv1.OperatorStatus) (*operatorv1.OperatorStatus, error) {
	original, err := c.Informers.Operator().V1().Authentications().Lister().Get("cluster")
	if err != nil {
		return nil, err
	}
	copy := original.DeepCopy()
	copy.ResourceVersion = resourceVersion
	copy.Status.OperatorStatus = *status

	ret, err := c.Client.Authentications().UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	return &ret.Status.OperatorStatus, nil
}
