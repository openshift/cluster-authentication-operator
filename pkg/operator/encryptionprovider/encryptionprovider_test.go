package encryptionprovider

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
)

func TestEncryptionProvider(t *testing.T) {
	encryptionCfgAnnotationKey := "ec-key"
	defaultGRs := []schema.GroupResource{
		{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
		{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
	}

	scenarios := []struct {
		name                            string
		initialSecrets                  []*corev1.Secret
		defaultEncryptedGRs             []schema.GroupResource
		expectedEncryptedGRs            []schema.GroupResource
		expectedShouldRunEncryptionCtrl bool
	}{
		{
			name:                            "encryption off, default GRs returned",
			defaultEncryptedGRs:             defaultGRs,
			expectedShouldRunEncryptionCtrl: false,
		},
		{
			name: "encryption on, secret without the annotation, default GRs returned",
			initialSecrets: []*corev1.Secret{
				func() *corev1.Secret {
					s := defaultSecret("openshift-apiserver", encryptionCfgAnnotationKey)
					delete(s.Annotations, encryptionCfgAnnotationKey)
					return s
				}(),
			},
			defaultEncryptedGRs:             defaultGRs,
			expectedEncryptedGRs:            defaultGRs,
			expectedShouldRunEncryptionCtrl: true,
		},
		{
			name:                            "encryption on, secret with the annotation, reduced GRs returned",
			initialSecrets:                  []*corev1.Secret{defaultSecret("openshift-apiserver", encryptionCfgAnnotationKey)},
			defaultEncryptedGRs:             defaultGRs,
			expectedShouldRunEncryptionCtrl: false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			fakeSecretsIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, secret := range scenario.initialSecrets {
				fakeSecretsIndexer.Add(secret)
			}
			fakeSecretsLister := corev1listers.NewSecretLister(fakeSecretsIndexer)

			// act
			target := encryptionProvider{
				targetNamespace:            "openshift-apiserver",
				encryptionCfgAnnotationKey: encryptionCfgAnnotationKey,
				authoritativeEncryptedGRs:  scenario.defaultEncryptedGRs,
				secretLister:               fakeSecretsLister.Secrets("openshift-config-managed"),
			}

			actualEncryptedGRs := target.EncryptedGRs()

			if !equality.Semantic.DeepEqual(actualEncryptedGRs, scenario.expectedEncryptedGRs) {
				t.Errorf("incorect GRs returned: %s", diff.ObjectDiff(actualEncryptedGRs, scenario.expectedEncryptedGRs))
			}

			shouldRun, err := target.ShouldRunEncryptionControllers()
			if err != nil {
				t.Errorf("ShouldRunEncryptionControllers returned an unexpected error %v", err)
			}
			if shouldRun != scenario.expectedShouldRunEncryptionCtrl {
				t.Errorf("expected ShouldRunEncryptionControllers to return %v but got %v", scenario.expectedShouldRunEncryptionCtrl, shouldRun)
			}
		})
	}
}

func defaultSecret(name, annotation string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, name),
			Namespace: "openshift-config-managed",
			Annotations: map[string]string{
				annotation: "value",
			},
		},
		Data: map[string][]byte{"encryption-config": {0xFF}},
	}
}
