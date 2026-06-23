package kmshealthwriter

import (
	"context"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// NewEncryptionStatusWriter satisfies health.NewEncryptionStatusWriterFunc.
// Only the operator itself knows where to apply the KMSEncryptionStatus.
func NewEncryptionStatusWriter(restConfig *rest.Config, fieldManager string) (health.EncryptionStatusWriter, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
		_, err := client.OperatorV1().Authentications().ApplyStatus(
			ctx,
			applyoperatorv1.Authentication("cluster").
				WithStatus(applyoperatorv1.AuthenticationStatus().WithOAuthAPIServer(
					applyoperatorv1.OAuthAPIServerStatus().WithEncryptionStatus(status),
				)),
			metav1.ApplyOptions{FieldManager: fieldManager, Force: true},
		)
		return err
	}, nil
}
