package encryptionstatusprovider

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	operatorv1typed "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
)

// NewAuthenticationEncryptionStatusProvider builds a kms.EncryptionStatusProvider
// for Authentication/cluster from an operator client. It reads and writes the encryption
// status at .status.oauthAPIServer.encryptionStatus.
func NewAuthenticationEncryptionStatusProvider(client operatorclient.Interface) (kms.EncryptionStatusProvider, error) {
	return &authenticationEncryptionStatusProvider{client: client.OperatorV1().Authentications()}, nil
}

var _ kms.EncryptionStatusProvider = &authenticationEncryptionStatusProvider{}

type authenticationEncryptionStatusProvider struct {
	client operatorv1typed.AuthenticationInterface
}

func (p *authenticationEncryptionStatusProvider) GetKMSEncryptionStatus(ctx context.Context) (*operatorv1.KMSEncryptionStatus, error) {
	obj, err := p.client.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &obj.Status.OAuthAPIServer.EncryptionStatus, nil
}

func (p *authenticationEncryptionStatusProvider) ApplyKMSEncryptionStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	_, err := p.client.ApplyStatus(
		ctx,
		applyoperatorv1.Authentication("cluster").WithStatus(
			applyoperatorv1.AuthenticationStatus().WithOAuthAPIServer(
				applyoperatorv1.OAuthAPIServerStatus().WithEncryptionStatus(status),
			),
		),
		metav1.ApplyOptions{FieldManager: fieldManager, Force: true},
	)
	return err
}

func (p *authenticationEncryptionStatusProvider) UpdateKMSEncryptionStatus(ctx context.Context, mutateFn func(*operatorv1.KMSEncryptionStatus)) error {
	obj, err := p.client.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return err
	}
	mutateFn(&obj.Status.OAuthAPIServer.EncryptionStatus)
	_, err = p.client.UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}
