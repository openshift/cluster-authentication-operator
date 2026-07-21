package encryptionstatusprovider

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
)

// NewAuthenticationEncryptionStatusProviderFromConfig builds a kms.EncryptionStatusProvider
// for Authentication/cluster from a rest.Config. It reads and writes the encryption
// status at .status.oauthAPIServer.encryptionStatus.
func NewAuthenticationEncryptionStatusProviderFromConfig(restConfig *rest.Config) (kms.EncryptionStatusProvider, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("build operator client: %w", err)
	}
	return &authenticationEncryptionStatusProvider{client: client}, nil
}

var _ kms.EncryptionStatusProvider = &authenticationEncryptionStatusProvider{}

type authenticationEncryptionStatusProvider struct {
	client *operatorclient.Clientset
}

func (p *authenticationEncryptionStatusProvider) GetKMSEncryptionStatus(ctx context.Context) (*operatorv1.KMSEncryptionStatus, error) {
	obj, err := p.client.OperatorV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &obj.Status.OAuthAPIServer.EncryptionStatus, nil
}

func (p *authenticationEncryptionStatusProvider) ApplyKMSEncryptionStatus(ctx context.Context, fieldManager string, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	_, err := p.client.OperatorV1().Authentications().ApplyStatus(
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
