package e2e_encryption

import (
	"context"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	test "github.com/openshift/cluster-authentication-operator/test/library"
	library "github.com/openshift/library-go/test/library/encryption"
)

var _ = g.Describe("[sig-auth] authentication operator", func() {
	g.It("[Encryption][Serial] TestEncryptionTypeIdentity", func(ctx context.Context) {
		testEncryptionTypeIdentity(ctx, g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTypeUnset [Timeout:30m]", func(ctx context.Context) {
		testEncryptionTypeUnset(ctx, g.GinkgoTB())
	})

	g.It("[Encryption][Serial] TestEncryptionTurnOnAndOff [Timeout:60m]", func(ctx context.Context) {
		testEncryptionTurnOnAndOff(ctx, g.GinkgoTB())
	})
})

func testEncryptionTypeIdentity(ctx context.Context, tt testing.TB) {
	library.TestEncryptionTypeIdentity(ctx, tt, library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
		EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       library.WellKnownAuthTargetGRs,
		AssertFunc:                      library.AssertWellKnownTokens,
	})
}

func testEncryptionTypeUnset(ctx context.Context, tt testing.TB) {
	scenario := library.BasicScenario{
		Namespace:                       "openshift-config-managed",
		LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
		EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
		EncryptionConfigSecretNamespace: "openshift-config-managed",
		OperatorNamespace:               "openshift-authentication-operator",
		TargetGRs:                       library.WellKnownAuthTargetGRs,
		AssertFunc:                      library.AssertWellKnownTokens,
	}

	tt.Logf("Starting custom TestEncryptionTypeUnset with migration wait logic")

	e := library.NewE(tt, library.PrintEventsOnFailure(scenario.OperatorNamespace))

	clientSet := library.SetAndWaitForEncryptionType(ctx, e, library.EncryptionProvider{},
		scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)

	tt.Logf("Waiting for OAuth token migration to complete...")
	waitForOAuthMigrationComplete(ctx, tt, clientSet, 20*time.Minute)

	tt.Logf("Waiting for authentication operator to become ready...")
	waitForAuthOperatorReady(ctx, tt, clientSet, 20*time.Minute)

	tt.Logf("Asserting tokens are unencrypted...")
	scenario.AssertFunc(e, clientSet, configv1.EncryptionTypeIdentity,
		scenario.Namespace, scenario.LabelSelector)

	tt.Logf("TestEncryptionTypeUnset completed successfully")
}

func waitForOAuthMigrationComplete(ctx context.Context, t testing.TB, clientSet library.ClientSet, timeout time.Duration) {
	t.Helper()

	migrationNames := []string{
		"encryption-migration-oauth.openshift.io-oauthaccesstokens",
		"encryption-migration-oauth.openshift.io-oauthauthorizetokens",
	}

	gvr := schema.GroupVersionResource{
		Group:    "migration.k8s.io",
		Version:  "v1alpha1",
		Resource: "storageversionmigrations",
	}

	for _, migrationName := range migrationNames {
		t.Logf("Waiting for StorageVersionMigration %q to complete (timeout: %v)", migrationName, timeout)

		err := wait.PollImmediate(30*time.Second, timeout, func() (bool, error) {
			unstructuredObj, err := clientSet.DynamicClient.Resource(gvr).Get(ctx, migrationName, metav1.GetOptions{})
			if err != nil {
				t.Logf("  StorageVersionMigration %q not found or error: %v (will retry)", migrationName, err)
				return false, nil
			}

			status, found, err := unstructured.NestedMap(unstructuredObj.Object, "status")
			if err != nil || !found {
				t.Logf("  StorageVersionMigration %q has no status yet (will retry)", migrationName)
				return false, nil
			}

			conditions, found, err := unstructured.NestedSlice(status, "conditions")
			if err != nil || !found {
				t.Logf("  StorageVersionMigration %q has no conditions yet (will retry)", migrationName)
				return false, nil
			}

			for _, condObj := range conditions {
				cond, ok := condObj.(map[string]interface{})
				if !ok {
					continue
				}

				condType, _, _ := unstructured.NestedString(cond, "type")
				condStatus, _, _ := unstructured.NestedString(cond, "status")

				if condType == "Succeeded" && condStatus == "True" {
					t.Logf("  StorageVersionMigration %q succeeded", migrationName)
					return true, nil
				}

				if condType == "Running" && condStatus == "False" {
					reason, _, _ := unstructured.NestedString(cond, "reason")
					if reason == "Succeeded" || reason == "" {
						t.Logf("  StorageVersionMigration %q completed (Running=False)", migrationName)
						return true, nil
					}
					t.Logf("  StorageVersionMigration %q stopped running but reason: %s", migrationName, reason)
					return false, nil
				}
			}

			t.Logf("  StorageVersionMigration %q still in progress...", migrationName)
			return false, nil
		})

		if err != nil {
			t.Logf("WARNING: Failed to confirm StorageVersionMigration %q completion: %v", migrationName, err)
			t.Logf("Continuing anyway as migration may have already completed...")
		}
	}
}

func waitForAuthOperatorReady(ctx context.Context, t testing.TB, clientSet library.ClientSet, timeout time.Duration) {
	t.Helper()

	t.Logf("Waiting for authentication ClusterOperator Progressing=False (timeout: %v)", timeout)

	configClient, err := configclient.NewForConfig(test.NewClientConfigForTest(t))
	require.NoError(t, err)

	err = wait.PollImmediate(30*time.Second, timeout, func() (bool, error) {
		co, err := configClient.ConfigV1().ClusterOperators().Get(ctx, "authentication", metav1.GetOptions{})
		if err != nil {
			t.Logf("  Error getting authentication ClusterOperator: %v (will retry)", err)
			return false, nil
		}

		for _, condition := range co.Status.Conditions {
			if condition.Type == "Progressing" {
				if condition.Status == "False" {
					t.Logf("  Authentication operator is no longer progressing")
					return true, nil
				}
				t.Logf("  Authentication operator still progressing: %s (reason: %s)",
					condition.Message, condition.Reason)
				return false, nil
			}
		}

		t.Logf("  No Progressing condition found (will retry)")
		return false, nil
	})

	require.NoError(t, err, "Timed out waiting for authentication operator to stop progressing")
}

func testEncryptionTurnOnAndOff(ctx context.Context, tt testing.TB) {
	library.TestEncryptionTurnOnAndOff(ctx, tt, library.OnOffScenario{
		BasicScenario: library.BasicScenario{
			Namespace:                       "openshift-config-managed",
			LabelSelector:                   "encryption.apiserver.operator.openshift.io/component=openshift-oauth-apiserver",
			EncryptionConfigSecretName:      "encryption-config-openshift-oauth-apiserver",
			EncryptionConfigSecretNamespace: "openshift-config-managed",
			OperatorNamespace:               "openshift-authentication-operator",
			TargetGRs:                       library.WellKnownAuthTargetGRs,
			AssertFunc:                      library.AssertWellKnownTokens,
		},
		CreateResourceFunc: func(t testing.TB, _ library.ClientSet, _ string) runtime.Object {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			t.Cleanup(cancel)
			return library.CreateAndStoreWellKnownTokenOfLife(ctx, t, library.GetClients(t))
		},
		AssertResourceEncryptedFunc:    library.AssertWellKnownTokenOfLifeEncrypted,
		AssertResourceNotEncryptedFunc: library.AssertWellKnownTokenOfLifeNotEncrypted,
		ResourceFunc:                   library.WellKnownTokenOfLife,
		ResourceName:                   "TokenOfLife",
		EncryptionProvider: library.EncryptionProvider{
			APIServerEncryption: configv1.APIServerEncryption{Type: configv1.EncryptionType("aescbc")},
		},
	})
}
