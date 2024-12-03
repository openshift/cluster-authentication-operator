package oauthclientsswitchedinformer

import (
	"context"
	"time"

	oauthinformersv1 "github.com/openshift/client-go/oauth/informers/externalversions/oauth/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// InformerWithSwitch is a controller that can start and stop an informer based on
// a condition func (shouldStopFn), that returns a bool and an error. If an error
// is returned, then the controller's sync will fail with that error. If no error
// is returned, then the controller stops/starts the informer based on the bool value
// (true means stop).
type InformerWithSwitch struct {
	delegateInformer oauthinformersv1.OAuthClientInformer
	switchController factory.Controller
	shouldStopFn     func() (bool, error)
	parentCtx        context.Context
	runCtx           context.Context
	stopFunc         func()
}

type alwaysSyncedInformer struct {
	isRunning func() bool
	cache.SharedIndexInformer
}

// HasSynced returns true when the informer's caches have synced, false otherwise.
// Since the SwitchedInformer can be stopped, waiting for its cache to sync can lead to
// timeouts, as a stopped informer will never sync. We override the HasSynced()
// method to always return true when stopped; clients should explicitly call cache.WaitForCacheSync.
func (s *alwaysSyncedInformer) HasSynced() bool {
	if s.isRunning() {
		return s.SharedIndexInformer.HasSynced()
	}
	return true
}

func NewSwitchedInformer(
	name string,
	ctx context.Context,
	shouldStopFn func() (bool, error),
	delegateInformer oauthinformersv1.OAuthClientInformer,
	resync time.Duration,
	informers []factory.Informer,
	recorder events.Recorder,
) *InformerWithSwitch {

	s := &InformerWithSwitch{
		parentCtx:        ctx,
		delegateInformer: delegateInformer,
		shouldStopFn:     shouldStopFn,
	}

	controllerFactory := factory.New().WithSync(s.sync)

	if len(informers) > 0 {
		controllerFactory.WithInformers(informers...)
	}

	if resync > 0 {
		controllerFactory.ResyncEvery(resync)
	}

	s.switchController = controllerFactory.ToController(name, recorder)
	return s
}

func (s *InformerWithSwitch) Controller() factory.Controller {
	return s.switchController
}

func (s *InformerWithSwitch) Informer() cache.SharedIndexInformer {
	return &alwaysSyncedInformer{
		isRunning:           func() bool { return s.runCtx != nil },
		SharedIndexInformer: s.delegateInformer.Informer(),
	}
}

func (s *InformerWithSwitch) Start(stopCh <-chan struct{}) {
	go s.switchController.Run(s.parentCtx, 1)
	go func() {
		<-stopCh
		s.stop()
	}()
}

func (s *InformerWithSwitch) ensureRunning() {
	if s.runCtx != nil {
		return
	}

	klog.Infof("%s delegate informer starting", s.switchController.Name())
	s.runCtx, s.stopFunc = context.WithCancel(s.parentCtx)
	go s.delegateInformer.Informer().Run(s.runCtx.Done())
}

func (s *InformerWithSwitch) stop() {
	if s.runCtx == nil {
		return
	}

	klog.Infof("%s delegate informer stopping", s.switchController.Name())
	s.stopFunc()
	s.runCtx = nil
	s.stopFunc = nil
}

func (s *InformerWithSwitch) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if s.shouldStopFn != nil {
		shouldStop, err := s.shouldStopFn()
		if err != nil {
			return err
		}

		if shouldStop {
			s.stop()
			return nil
		}
	}

	s.ensureRunning()
	return nil
}
