package encryption

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

// testEncryptionTypeBase is a common helper that reduces duplication across encryption type tests.
func testEncryptionTypeBase(tb testing.TB, scenario library.BasicScenario, encryptionType configv1.EncryptionType, expectedType configv1.EncryptionType) {
	if encryptionType == "" {
		tb.Logf("Starting encryption e2e test for unset mode (defaults to identity)")
	} else {
		tb.Logf("Starting encryption e2e test for %q mode", encryptionType)
	}

	clientSet := SetAndWaitForEncryptionType(tb, encryptionType, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)
	libClientSet := clientSet.toLibraryClientSet()

	scenario.AssertFunc(tb, libClientSet, expectedType, scenario.Namespace, scenario.LabelSelector)

	// For actual encryption types (not identity/unset), also assert encryption config
	if encryptionType != "" && encryptionType != configv1.EncryptionTypeIdentity {
		library.AssertEncryptionConfig(tb, libClientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
	}
}

// TestEncryptionTypeIdentity tests encryption with identity mode (no encryption).
// This is a local implementation that accepts testing.TB instead of *testing.T
// to be compatible with Ginkgo v2's GinkgoTB().
func TestEncryptionTypeIdentity(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, configv1.EncryptionTypeIdentity, configv1.EncryptionTypeIdentity)
}

// TestEncryptionTypeUnset tests encryption with unset type (defaults to identity).
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionTypeUnset(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, "", configv1.EncryptionTypeIdentity)
}

// TestEncryptionTypeAESCBC tests encryption with AESCBC mode.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionTypeAESCBC(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, configv1.EncryptionTypeAESCBC, configv1.EncryptionTypeAESCBC)
}

// TestEncryptionTypeAESGCM tests encryption with AESGCM mode.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionTypeAESGCM(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, configv1.EncryptionTypeAESGCM, configv1.EncryptionTypeAESGCM)
}

// TestEncryptionType is a helper that dispatches to the appropriate encryption type test.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionType(tb testing.TB, scenario library.BasicScenario, provider configv1.EncryptionType) {
	switch provider {
	case configv1.EncryptionTypeAESCBC:
		TestEncryptionTypeAESCBC(tb, scenario)
	case configv1.EncryptionTypeAESGCM:
		TestEncryptionTypeAESGCM(tb, scenario)
	case configv1.EncryptionTypeIdentity, "":
		TestEncryptionTypeIdentity(tb, scenario)
	default:
		tb.Fatalf("Unknown encryption type: %s", provider)
	}
}

// TestEncryptionTurnOnAndOff tests turning encryption on and off.
// This is a local implementation that accepts testing.TB instead of *testing.T.
// It runs through a complete cycle twice to ensure repeatability:
// 1. Create resource -> Enable encryption -> Verify encrypted -> Disable -> Verify not encrypted
// 2. Repeat the cycle to ensure it works multiple times
func TestEncryptionTurnOnAndOff(tb testing.TB, scenario library.OnOffScenario) {
	tb.Logf("Starting encryption turn-on-and-off test for resource %q", scenario.ResourceName)

	// Helper to get library clientset - uses shared helper function
	getLibClientSet := func() library.ClientSet {
		return createLibraryClientSet(tb)
	}

	// Step 1: Create and store the resource
	tb.Logf("Step 1/9: Creating and storing %s", scenario.ResourceName)
	scenario.CreateResourceFunc(tb, getLibClientSet(), scenario.Namespace)

	// Step 2: Turn on encryption with the specified provider
	tb.Logf("Step 2/9: Enabling %s encryption", scenario.EncryptionProvider)
	TestEncryptionType(tb, scenario.BasicScenario, scenario.EncryptionProvider)

	// Step 3: Assert the resource is encrypted
	tb.Logf("Step 3/9: Verifying %s is encrypted", scenario.ResourceName)
	scenario.AssertResourceEncryptedFunc(tb, getLibClientSet(), scenario.ResourceFunc(tb, scenario.Namespace))

	// Step 4: Turn off encryption (switch to identity mode)
	tb.Logf("Step 4/9: Disabling encryption (switching to identity mode)")
	TestEncryptionTypeIdentity(tb, scenario.BasicScenario)

	// Step 5: Assert the resource is not encrypted
	tb.Logf("Step 5/9: Verifying %s is not encrypted", scenario.ResourceName)
	scenario.AssertResourceNotEncryptedFunc(tb, getLibClientSet(), scenario.ResourceFunc(tb, scenario.Namespace))

	// Step 6: Turn on encryption again (second cycle to test repeatability)
	tb.Logf("Step 6/9: Enabling %s encryption (second cycle)", scenario.EncryptionProvider)
	TestEncryptionType(tb, scenario.BasicScenario, scenario.EncryptionProvider)

	// Step 7: Assert the resource is encrypted again
	tb.Logf("Step 7/9: Verifying %s is encrypted (second cycle)", scenario.ResourceName)
	scenario.AssertResourceEncryptedFunc(tb, getLibClientSet(), scenario.ResourceFunc(tb, scenario.Namespace))

	// Step 8: Turn off encryption again (second cycle)
	tb.Logf("Step 8/9: Disabling encryption (identity mode, second cycle)")
	TestEncryptionTypeIdentity(tb, scenario.BasicScenario)

	// Step 9: Assert the resource is not encrypted again
	tb.Logf("Step 9/9: Verifying %s is not encrypted (second cycle)", scenario.ResourceName)
	scenario.AssertResourceNotEncryptedFunc(tb, getLibClientSet(), scenario.ResourceFunc(tb, scenario.Namespace))

	tb.Logf("Encryption turn-on-and-off test completed successfully")
}

// TestEncryptionRotation tests encryption key rotation.
// This is a local implementation that accepts testing.TB instead of *testing.T.
// It first encrypts data with the specified encryption provider key,
// then forces a key rotation and verifies the resource is re-encrypted with a new key.
func TestEncryptionRotation(tb testing.TB, scenario library.RotationScenario) {
	tb.Logf("Starting encryption rotation test for %q provider", scenario.EncryptionProvider)

	// Test data
	ns := scenario.Namespace
	labelSelector := scenario.LabelSelector

	// Get library clientset using shared helper
	libClientSet := createLibraryClientSet(tb)

	// Step 1: Create the desired resource
	tb.Logf("Step 1/5: Creating test resource")
	scenario.CreateResourceFunc(tb, libClientSet, ns)

	// Step 2: Run provided encryption scenario (enable encryption)
	tb.Logf("Step 2/5: Enabling %s encryption", scenario.EncryptionProvider)
	TestEncryptionType(tb, scenario.BasicScenario, scenario.EncryptionProvider)

	// Step 3: Take samples (get encrypted resource content with first key)
	tb.Logf("Step 3/5: Capturing encrypted resource state with first key")
	rawEncryptedResourceWithKey1 := scenario.GetRawResourceFunc(tb, libClientSet, ns)

	// Step 4: Force key rotation and wait for migration to complete
	tb.Logf("Step 4/5: Forcing key rotation and waiting for migration")
	lastMigratedKeyMeta, err := library.GetLastKeyMeta(tb, libClientSet.Kube, ns, labelSelector)
	require.NoError(tb, err)
	require.NoError(tb, library.ForceKeyRotation(tb, scenario.UnsupportedConfigFunc, fmt.Sprintf("test-key-rotation-%s", rand.String(4))))
	library.WaitForNextMigratedKey(tb, libClientSet.Kube, lastMigratedKeyMeta, scenario.TargetGRs, ns, labelSelector)
	scenario.AssertFunc(tb, libClientSet, scenario.EncryptionProvider, ns, labelSelector)

	// Step 5: Verify the resource was encrypted with a different key (compare step 3 vs step 4)
	tb.Logf("Step 5/5: Verifying resource was re-encrypted with new key")
	rawEncryptedResourceWithKey2 := scenario.GetRawResourceFunc(tb, libClientSet, ns)
	if rawEncryptedResourceWithKey1 == rawEncryptedResourceWithKey2 {
		tb.Errorf("expected the resource to have different content after key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedResourceWithKey1, rawEncryptedResourceWithKey2)
	}

	tb.Logf("Encryption rotation test completed successfully")
}

// TestPerfEncryption tests encryption performance.
// This is a local implementation that accepts testing.TB instead of *testing.T.
// It populates the database with test data, enables encryption, and measures migration time.
func TestPerfEncryption(tb testing.TB, scenario library.PerfScenario) {
	tb.Logf("Starting encryption performance test for %q provider", scenario.EncryptionProvider)

	migrationStartedCh := make(chan time.Time, 1)

	// Step 1: Populate the database with test data
	tb.Logf("Step 1/3: Populating database with test data using %d workers", scenario.DBLoaderWorkers)
	populateDatabase(tb, scenario.DBLoaderWorkers, scenario.DBLoaderFunc, scenario.AssertDBPopulatedFunc)

	// Step 2: Start watching for migration controller progressing condition asynchronously
	tb.Logf("Step 2/3: Starting migration progress monitor")
	watchForMigrationControllerProgressingConditionAsync(tb, scenario.GetOperatorConditionsFunc, migrationStartedCh)

	// Step 3: Run encryption test and measure time
	tb.Logf("Step 3/3: Enabling encryption and measuring migration time")
	endTimeStamp := runTestEncryptionPerf(tb, scenario)

	// Calculate and assert migration time
	select {
	case migrationStarted := <-migrationStartedCh:
		migrationTime := endTimeStamp.Sub(migrationStarted)
		tb.Logf("Migration completed in %v", migrationTime)
		scenario.AssertMigrationTime(tb, migrationTime)
	default:
		tb.Error("unable to calculate the migration time, failed to observe when the migration has started")
	}

	tb.Logf("Encryption performance test completed")
}

// runTestEncryptionPerf is a helper that runs the encryption test and captures the end timestamp.
func runTestEncryptionPerf(tb testing.TB, scenario library.PerfScenario) time.Time {
	var ts time.Time
	TestEncryptionType(tb, library.BasicScenario{
		Namespace:                       scenario.Namespace,
		LabelSelector:                   scenario.LabelSelector,
		EncryptionConfigSecretName:      scenario.EncryptionConfigSecretName,
		EncryptionConfigSecretNamespace: scenario.EncryptionConfigSecretNamespace,
		OperatorNamespace:               scenario.OperatorNamespace,
		TargetGRs:                       scenario.TargetGRs,
		AssertFunc: func(t testing.TB, clientSet library.ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
			// Note that AssertFunc is executed after an encryption secret has been annotated
			ts = time.Now()
			scenario.AssertFunc(t, clientSet, expectedMode, scenario.Namespace, scenario.LabelSelector)
			t.Logf("AssertFunc for TestEncryption scenario with %q provider took %v", scenario.EncryptionProvider, time.Since(ts))
		},
	}, scenario.EncryptionProvider)
	return ts
}

// LocalClientSet represents the client set for local encryption tests.
// This matches the structure of library.ClientSet but is defined locally.
type LocalClientSet struct {
	Etcd            library.EtcdClient
	ApiServerConfig configv1client.APIServerInterface
	Kube            kubernetes.Interface
}

// toLibraryClientSet converts LocalClientSet to library.ClientSet.
func (lcs LocalClientSet) toLibraryClientSet() library.ClientSet {
	return library.ClientSet{
		Etcd:            lcs.Etcd,
		ApiServerConfig: lcs.ApiServerConfig,
		Kube:            lcs.Kube,
	}
}

// createLibraryClientSet creates a library.ClientSet from kubeconfig.
// This helper consolidates the duplicated clientset creation logic.
func createLibraryClientSet(tb testing.TB) library.ClientSet {
	kubeConfig := NewClientConfigForTest(tb)
	libClientSet := library.ClientSet{}
	libClientSet.Kube = kubernetes.NewForConfigOrDie(kubeConfig)
	libClientSet.Etcd = library.NewEtcdClient(libClientSet.Kube)
	configClient := configv1client.NewForConfigOrDie(kubeConfig)
	libClientSet.ApiServerConfig = configClient.APIServers()
	return libClientSet
}

// SetAndWaitForEncryptionType sets the encryption type and waits for it to be applied.
// This is a local helper that works with testing.TB and uses local GetClients.
func SetAndWaitForEncryptionType(tb testing.TB, encryptionType configv1.EncryptionType, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) LocalClientSet {
	// Create library clientset using shared helper
	libClientSet := createLibraryClientSet(tb)

	lastMigratedKeyMeta, err := library.GetLastKeyMeta(tb, libClientSet.Kube, namespace, labelSelector)
	require.NoError(tb, err)

	// Get current API server config
	apiServer, err := libClientSet.ApiServerConfig.Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(tb, err)

	// Update encryption type if needed
	needsUpdate := apiServer.Spec.Encryption.Type != encryptionType
	if needsUpdate {
		tb.Logf("Updating encryption type in the config file for APIServer to %q", encryptionType)
		apiServer.Spec.Encryption.Type = encryptionType
		_, err = libClientSet.ApiServerConfig.Update(context.TODO(), apiServer, metav1.UpdateOptions{})
		require.NoError(tb, err)
	} else {
		tb.Logf("APIServer is already configured to use %q mode", encryptionType)
	}

	library.WaitForEncryptionKeyBasedOn(tb, libClientSet.Kube, lastMigratedKeyMeta, encryptionType, defaultTargetGRs, namespace, labelSelector)

	return LocalClientSet{
		Etcd:            libClientSet.Etcd,
		ApiServerConfig: libClientSet.ApiServerConfig,
		Kube:            libClientSet.Kube,
	}
}
