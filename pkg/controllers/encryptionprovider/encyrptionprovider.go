package encryptionprovider

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type encryptionProvider struct {
	targetNamespace                       string
	globalMachineSpecifiedConfigNamespace string
	encryptionCfgAnnotationKey            string

	authoritativeEncryptedGRs []schema.GroupResource

	secretLister corev1listers.SecretNamespaceLister
}

var _ controllers.Provider = &encryptionProvider{}

func New(
	targetNamespace string,
	globalMachineSpecifiedConfigNamespace string,
	encryptionCfgAnnotationKey string,
	defaultEncryptedGRs []schema.GroupResource,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces) *encryptionProvider {
	return &encryptionProvider{
		targetNamespace:            targetNamespace,
		encryptionCfgAnnotationKey: encryptionCfgAnnotationKey,
		authoritativeEncryptedGRs:  defaultEncryptedGRs,
		secretLister:               kubeInformersForNamespaces.InformersFor(globalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Lister().Secrets(globalMachineSpecifiedConfigNamespace),
	}
}

// EncryptedGRs returns resources that need to be encrypted
// Note: the list can change depending on the existence and attached annotations of encryption-config-openshift-oauth-apiserver in openshift-config-managed namespace as described in https://github.com/openshift/enhancements/blob/master/enhancements/etcd/etcd-encryption-for-separate-oauth-apis.md
//
// case 1 encryption off or the secret was annotated - return an empty list of EncryptedGRs
// case 2 otherwise return the authoritative list of EncryptedGRs
//
// TODO:
// - change the code in 4.7 to return a static list (the authoritative list)
func (p *encryptionProvider) EncryptedGRs() []schema.GroupResource {
	inCharge, err := p.isOAuthEncryptionConfigManagedByThisOperator()
	if err != nil || !inCharge {
		return []schema.GroupResource{}
	}

	return p.authoritativeEncryptedGRs
}

// ShouldRunEncryptionControllers indicates whether external preconditions are satisfied so that encryption controllers can start synchronizing
func (p *encryptionProvider) ShouldRunEncryptionControllers() (bool, error) {
	return p.isOAuthEncryptionConfigManagedByThisOperator()
}

// isOAuthEncryptionConfigManagedByThisOperator determines whether this operator is in charge of encryption-config-openshift-oauth-apiserver
//
// case 1 encryption off or the secret was annotated - OAS-O is in charge
// case 2 otherwise this operator will manage its own encryption configuration
// TODO:
// - change the case 1 in 4.7 so that CAO manages its own encryption config when encryption is off
func (p *encryptionProvider) isOAuthEncryptionConfigManagedByThisOperator() (bool, error) {
	oauthAPIServerEncryptionCfgName := fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, p.targetNamespace)
	oauthAPIServerEncryptionCfg, err := p.secretLister.Get(oauthAPIServerEncryptionCfgName)
	if err != nil {
		// note that it's okay to return false on an error because:
		// - the only type of error we can get here (cache) is NotFound which means that the encryption is off
		// - we suppress the error so that the encryption controllers:
		//    1. don't report Degraded when encryption is off
		//    2. don't requeue when encryption is off
		return false, nil // case 1 - OAS-O in charge
	}
	if _, exist := oauthAPIServerEncryptionCfg.Annotations[p.encryptionCfgAnnotationKey]; exist {
		return false, nil // case 1 - OAS-O in charge
	}
	return true, nil // case 2 - taking over
}
