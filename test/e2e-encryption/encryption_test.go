package e2eencryption

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	operatorencryption "github.com/openshift/cluster-authentication-operator/test/library/encryption"
	library "github.com/openshift/library-go/test/library/encryption"
)

func TestEncryptionTypeIdentity(t *testing.T) {
	library.TestEncryptionTypeIdentity(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       operatorencryption.DefaultTargetGRs,
		AssertFunc:                      operatorencryption.AssertTokens,
	})
}

func TestEncryptionTypeUnset(t *testing.T) {
	library.TestEncryptionTypeUnset(t, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
		EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       operatorencryption.DefaultTargetGRs,
		AssertFunc:                      operatorencryption.AssertTokens,
	})
}

func TestEncryptionTurnOnAndOff(t *testing.T) {
	library.TestEncryptionTurnOnAndOff(t, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component" + "=" + "openshift-oauth-apiserver",
			EncryptionConfigSecretName:      fmt.Sprintf("encryption-config-openshift-oauth-apiserver"),
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       operatorencryption.DefaultTargetGRs,
			AssertFunc:                      operatorencryption.AssertTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, namespace string) runtime.Object {
			return operatorencryption.CreateAndStoreTokenOfLife(context.TODO(), t, operatorencryption.GetClients(t))
		},
		AssertResourceEncryptedFunc:    operatorencryption.AssertTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: operatorencryption.AssertTokenOfLifeNotEncrypted,
		ResourceFunc:                   func(t testing.TB, _ string) runtime.Object { return operatorencryption.TokenOfLife(t) },
		ResourceName:                   "TokenOfLife",
	})
}
