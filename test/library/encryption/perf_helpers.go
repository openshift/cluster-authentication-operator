package encryption

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/openshift/api/operator/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

const (
	waitPollInterval = 15 * time.Second
	waitPollTimeout  = 69*time.Minute + 10*time.Minute
)

// watchForMigrationControllerProgressingConditionAsync starts watching for the migration
// controller progressing condition in a background goroutine.
func watchForMigrationControllerProgressingConditionAsync(t testing.TB, getOperatorCondFn library.GetOperatorConditionsFuncType, migrationStartedCh chan time.Time) {
	t.Helper()
	go watchForMigrationControllerProgressingCondition(t, getOperatorCondFn, migrationStartedCh)
}

// watchForMigrationControllerProgressingCondition waits for the EncryptionMigrationControllerProgressing
// condition to be set to true and sends the start time to the channel.
func watchForMigrationControllerProgressingCondition(t testing.TB, getOperatorConditionsFn library.GetOperatorConditionsFuncType, migrationStartedCh chan time.Time) {
	t.Helper()

	t.Logf("Waiting up to %s for the condition %q with the reason %q to be set to true", waitPollTimeout.String(), "EncryptionMigrationControllerProgressing", "Migrating")
	err := wait.Poll(waitPollInterval, waitPollTimeout, func() (bool, error) {
		conditions, err := getOperatorConditionsFn(t)
		if err != nil {
			return false, err
		}
		for _, cond := range conditions {
			if cond.Type == "EncryptionMigrationControllerProgressing" && cond.Status == operatorv1.ConditionTrue {
				t.Logf("EncryptionMigrationControllerProgressing condition observed at %v", cond.LastTransitionTime)
				migrationStartedCh <- cond.LastTransitionTime.Time
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Logf("failed waiting for the condition %q with the reason %q to be set to true, err was %v", "EncryptionMigrationControllerProgressing", "Migrating", err)
	}
}

// populateDatabase populates the database using the provided loader function with multiple workers.
func populateDatabase(t testing.TB, workers int, dbLoaderFun library.DBLoaderFuncType, assertDBPopulatedFunc func(t testing.TB, errorStore map[string]int, statStore map[string]int)) {
	t.Helper()
	start := time.Now()
	defer func() {
		end := time.Now()
		t.Logf("Populating etcd took %v", end.Sub(start))
	}()

	r := newRunner()

	// run executes loaderFunc for each worker
	r.run(t, workers, dbLoaderFun)

	assertDBPopulatedFunc(t, r.errorStore, r.statsStore)
}

// runner manages parallel execution of database loader functions.
type runner struct {
	errorStore map[string]int
	lock       *sync.Mutex

	statsStore map[string]int
	lockStats  *sync.Mutex
	wg         *sync.WaitGroup
}

// newRunner creates a new runner for executing database load functions.
func newRunner() *runner {
	r := &runner{}

	r.errorStore = map[string]int{}
	r.lock = &sync.Mutex{}
	r.statsStore = map[string]int{}
	r.lockStats = &sync.Mutex{}

	r.wg = &sync.WaitGroup{}

	return r
}

// run executes the provided work functions using multiple workers.
func (r *runner) run(t testing.TB, workers int, workFunc ...library.DBLoaderFuncType) {
	t.Logf("Executing provided load function for %d workers", workers)
	for i := 0; i < workers; i++ {
		wrapper := func(wg *sync.WaitGroup) {
			defer wg.Done()
			kubeClient, err := newKubeClient(t, 300, 600)
			if err != nil {
				t.Errorf("Unable to create a kube client for a worker due to %v", err)
				r.collectError(err)
				return
			}
			_ = runWorkFunctions(kubeClient, "", r.collectError, r.collectStat, workFunc...)
		}
		r.wg.Add(1)
		go wrapper(r.wg)
	}
	r.wg.Wait()
	t.Log("All workers completed successfully")
}

// collectError collects and counts errors from workers.
func (r *runner) collectError(err error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	errCount, ok := r.errorStore[err.Error()]
	if !ok {
		r.errorStore[err.Error()] = 1
		return
	}
	errCount += 1
	r.errorStore[err.Error()] = errCount
}

// collectStat collects and counts statistics from workers.
func (r *runner) collectStat(stat string) {
	r.lockStats.Lock()
	defer r.lockStats.Unlock()
	statCount, ok := r.statsStore[stat]
	if !ok {
		r.statsStore[stat] = 1
		return
	}
	statCount += 1
	r.statsStore[stat] = statCount
}

// runWorkFunctions executes a series of database loader functions.
func runWorkFunctions(kubeClient kubernetes.Interface, namespace string, errorCollector func(error), statsCollector func(string), workFunc ...library.DBLoaderFuncType) error {
	if len(namespace) == 0 {
		namespace = createNamespaceName()
	}
	for _, work := range workFunc {
		err := work(kubeClient, namespace, errorCollector, statsCollector)
		if err != nil {
			errorCollector(err)
			return err
		}
	}
	return nil
}

// createNamespaceName generates a unique namespace name for testing.
func createNamespaceName() string {
	return fmt.Sprintf("encryption-%s", rand.String(10))
}

// newKubeClient creates a Kubernetes client with specified QPS and burst settings.
func newKubeClient(t testing.TB, qps float32, burst int) (kubernetes.Interface, error) {
	kubeConfig := NewClientConfigForTest(t)

	kubeConfig.QPS = qps
	kubeConfig.Burst = burst

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}
