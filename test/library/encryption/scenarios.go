package encryption

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

// TestPerfEncryption tests encryption performance.
// This is a local implementation that accepts testing.TB instead of *testing.T.
// It populates the database with test data, enables encryption, and measures migration time.
func TestPerfEncryption(tb testing.TB, scenario library.PerfScenario) {
	tb.Logf("Starting encryption performance test for %q provider", scenario.EncryptionProvider.Type)

	migrationStartedCh := make(chan time.Time, 1)

	// Create a cancelable context for the watcher goroutine to ensure it stops when the test finishes
	watcherCtx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)

	// Step 1: Populate the database with test data
	tb.Logf("Step 1/3: Populating database with test data using %d workers", scenario.DBLoaderWorkers)
	populateDatabase(tb, scenario.DBLoaderWorkers, scenario.DBLoaderFunc, scenario.AssertDBPopulatedFunc)

	// Step 2: Start watching for migration controller progressing condition asynchronously
	// Capture test start time to validate fresh condition transitions
	testStartTime := time.Now()
	tb.Logf("Step 2/3: Starting migration progress monitor (test start time: %v)", testStartTime)
	watchForMigrationControllerProgressingConditionAsync(watcherCtx, tb, scenario.GetOperatorConditionsFunc, migrationStartedCh, testStartTime)

	// Step 3: Run encryption test and measure time
	tb.Logf("Step 3/3: Enabling encryption and measuring migration time")
	endTimeStamp := runTestEncryptionPerf(tb, scenario)

	// Calculate and assert migration time
	select {
	case migrationStarted := <-migrationStartedCh:
		if migrationStarted.IsZero() {
			tb.Error("unable to calculate the migration time, migration watcher encountered an error")
		} else {
			migrationTime := endTimeStamp.Sub(migrationStarted)
			tb.Logf("Migration completed in %v", migrationTime)
			scenario.AssertMigrationTime(tb, migrationTime)
		}
	case <-time.After(30 * time.Second):
		tb.Error("unable to calculate the migration time, failed to observe when the migration has started")
	}

	tb.Logf("Encryption performance test completed")
}

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
			tb.Logf("AssertFunc for TestEncryption scenario with %q provider took %v", scenario.EncryptionProvider.Type, time.Since(ts))
		},
	}, scenario.EncryptionProvider)
	return ts
}

// TestEncryptionType is a helper that dispatches to the appropriate encryption type test.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionType(tb testing.TB, scenario library.BasicScenario, provider library.EncryptionProvider) {
	switch provider.Type {
	case configv1.EncryptionTypeAESCBC:
		TestEncryptionTypeAESCBC(tb, scenario)
	case configv1.EncryptionTypeAESGCM:
		TestEncryptionTypeAESGCM(tb, scenario)
	case configv1.EncryptionTypeKMS:
		TestEncryptionTypeKMS(tb, scenario)
	case configv1.EncryptionTypeIdentity:
		TestEncryptionTypeIdentity(tb, scenario)
	case "":
		TestEncryptionTypeUnset(tb, scenario)
	default:
		tb.Fatalf("Unknown encryption type: %s", provider.Type)
	}
}

// TestEncryptionTypeIdentity tests encryption with identity mode (no encryption).
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionTypeIdentity(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, configv1.EncryptionTypeIdentity, configv1.EncryptionTypeIdentity)
}

// TestEncryptionTypeUnset tests encryption with unset mode (defaults to identity).
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

// TestEncryptionTypeKMS tests KMS encryption.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func TestEncryptionTypeKMS(tb testing.TB, scenario library.BasicScenario) {
	testEncryptionTypeBase(tb, scenario, configv1.EncryptionTypeKMS, configv1.EncryptionTypeKMS)
}

// testEncryptionTypeBase is the base implementation for all encryption type tests.
func testEncryptionTypeBase(tb testing.TB, scenario library.BasicScenario, encryptionType configv1.EncryptionType, expectedType configv1.EncryptionType) {
	if encryptionType == "" {
		tb.Logf("Starting encryption e2e test for unset mode (defaults to identity)")
	} else {
		tb.Logf("Starting encryption e2e test for %q mode", encryptionType)
	}

	clientSet := SetAndWaitForEncryptionType(tb, encryptionType, scenario.TargetGRs, scenario.Namespace, scenario.LabelSelector)

	scenario.AssertFunc(tb, clientSet, expectedType, scenario.Namespace, scenario.LabelSelector)

	// For actual encryption types (not identity/unset), also assert encryption config
	if encryptionType != "" && encryptionType != configv1.EncryptionTypeIdentity {
		library.AssertEncryptionConfig(tb, clientSet, scenario.EncryptionConfigSecretName, scenario.EncryptionConfigSecretNamespace, scenario.TargetGRs)
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
	tb.Logf("Step 2/9: Enabling %s encryption", scenario.EncryptionProvider.Type)
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
	tb.Logf("Step 6/9: Enabling %s encryption (second cycle)", scenario.EncryptionProvider.Type)
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

// SetAndWaitForEncryptionType sets the encryption type and waits for encryption to complete.
// This is a local implementation that accepts testing.TB instead of *testing.T.
func SetAndWaitForEncryptionType(tb testing.TB, encryptionType configv1.EncryptionType, defaultTargetGRs []schema.GroupResource, namespace, labelSelector string) library.ClientSet {
	// Create library clientset using shared helper
	libClientSet := createLibraryClientSet(tb)

	lastMigratedKeyMeta, err := library.GetLastKeyMeta(tb, libClientSet.Kube, namespace, labelSelector)
	require.NoError(tb, err)

	// Update encryption type with retry on conflict
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		reqCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get current API server config
		apiServer, err := libClientSet.ApiServerConfig.Get(reqCtx, "cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}

		// Update encryption type if needed
		if apiServer.Spec.Encryption.Type != encryptionType {
			tb.Logf("Updating encryption type in the config file for APIServer to %q", encryptionType)
			apiServer.Spec.Encryption.Type = encryptionType
			_, err = libClientSet.ApiServerConfig.Update(reqCtx, apiServer, metav1.UpdateOptions{})
			return err
		}
		tb.Logf("APIServer is already configured to use %q mode", encryptionType)
		return nil
	})
	require.NoError(tb, err)

	library.WaitForEncryptionKeyBasedOn(tb, libClientSet.Kube, lastMigratedKeyMeta, encryptionType, defaultTargetGRs, namespace, labelSelector)

	return libClientSet
}
