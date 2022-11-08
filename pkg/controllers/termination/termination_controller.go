package termination

import (
	"context"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

// terminationController forces a restart of the auth operator when the console capability goes from disabled to enabled.
// This is necessary to get the console observer registered (which happens during operator startup) so it can manage
// the console publicAssetUrl, when the console is present.
// This controller only runs when the operator comes up on a cluster where console is disabled.  If the console
// is enabled when the operator comes up, this controller will not be run.
type terminationController struct {
	clusterVersionLister configlistersv1.ClusterVersionLister
	recorder             events.Recorder
}

func NewTerminationController(configInformer configinformers.SharedInformerFactory, recorder events.Recorder) factory.Controller {
	c := &terminationController{
		clusterVersionLister: configInformer.Config().V1().ClusterVersions().Lister(),
		recorder:             recorder,
	}
	return factory.New().WithInformers(
		configInformer.Config().V1().ClusterVersions().Informer(),
	).ResyncEvery(wait.Jitter(time.Minute, 1.0)).WithSync(c.sync).ToController("TerminationController", recorder.WithComponentSuffix("termination-controller"))
}

func (c *terminationController) sync(ctx context.Context, syncCtx factory.SyncContext) error {

	// check the ClusterVersion object to see if the console is currently enabled.
	// Since this controller only runs when the console capability is disabled at operator startup time
	// it is safe to conclude that if it sees the console enabled, it must restart the operator.
	enabled, err := isConsoleCapabilityEnabled(c.clusterVersionLister, c.recorder)
	if err != nil {
		klog.Errorf("Error checking if console capability is enabled: %v", err)
		return err
	}
	if !enabled {
		return nil
	}
	err = triggerRestart()
	if err != nil {
		klog.Errorf("Error triggering restart: %v", err)
	}
	return err
}

func isConsoleCapabilityEnabled(clusterVersions configlistersv1.ClusterVersionLister, recorder events.Recorder) (bool, error) {
	clusterVersionConfig, err := clusterVersions.Get("version")
	if err != nil {
		return false, err
	}

	for _, capability := range clusterVersionConfig.Status.Capabilities.EnabledCapabilities {
		if capability == configv1.ClusterVersionCapabilityConsole {
			recorder.Eventf("TerminationController", "Console capability enabled, restarting cluster authentication operator")
			klog.Infof("Console capability enabled, restarting cluster authentication operator")
			return true, nil
		}
	}
	return false, nil
}

func triggerRestart() error {
	// this file is an argument to --terminate-on-files in the operator deployment command, so when it is
	// created or updated, the operator will terminate and be restarted.
	f, err := os.OpenFile("/tmp/terminate", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		klog.Errorf("Failed to restart self due to: %v\n", err)
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(time.Now().String()); err != nil {
		klog.Errorf("Failed to restart self due to: %v\n", err)
	}
	return err
}
