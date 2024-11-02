package libraryapplyconfiguration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/manifestclient"
	"github.com/openshift/library-go/pkg/operator/events"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

type OperatorStarter interface {
	RunOnce(ctx context.Context) error
	Start(ctx context.Context) error
}

type SimpleOperatorStarter struct {
	Informers                 []SimplifiedInformerFactory
	ControllerNamedRunOnceFns []NamedRunOnce
	// ControllerRunFns is useful during a transition to coalesce the operator launching flow.
	ControllerRunFns []RunFunc
	// Controllers hold an optional list of controller names to run.
	// By default, all controllers are run.
	Controllers []string
}

var (
	_ OperatorStarter           = &SimpleOperatorStarter{}
	_ SimplifiedInformerFactory = generatedInformerFactory{}
	_ SimplifiedInformerFactory = dynamicInformerFactory{}
	_ SimplifiedInformerFactory = generatedNamespacedInformerFactory{}
)

func (a SimpleOperatorStarter) RunOnce(ctx context.Context) error {
	for _, informer := range a.Informers {
		informer.Start(ctx)
	}
	// wait for sync so that when NamedRunOnce is called the listers will be ready.
	// TODO add timeout
	for _, informer := range a.Informers {
		informer.WaitForCacheSync(ctx)
	}

	knownControllersSet := sets.NewString()
	duplicateControllerNames := []string{}
	for _, controllerRunner := range a.ControllerNamedRunOnceFns {
		if knownControllersSet.Has(controllerRunner.ControllerInstanceName()) {
			duplicateControllerNames = append(duplicateControllerNames, controllerRunner.ControllerInstanceName())
			continue
		}
		knownControllersSet.Insert(controllerRunner.ControllerInstanceName())
	}
	if len(duplicateControllerNames) > 0 {
		return fmt.Errorf("the following controllers were requested to run multiple times: %v", duplicateControllerNames)
	}

	controllersToRunSet := sets.NewString(a.Controllers...)
	if controllersToRunSet.Len() == 0 {
		controllersToRunSet = knownControllersSet
	}
	if unknownControllersToRun := controllersToRunSet.Difference(knownControllersSet); len(unknownControllersToRun) > 0 {
		return fmt.Errorf("requested unknown controllers to be run: %v, known controllers: %v", unknownControllersToRun.List(), knownControllersSet.List())
	}

	errs := []error{}
	for _, controllerRunner := range a.ControllerNamedRunOnceFns {
		func() {
			if !controllersToRunSet.Has(controllerRunner.ControllerInstanceName()) {
				return
			}
			localCtx, localCancel := context.WithTimeout(ctx, 1*time.Second)
			defer localCancel()
			localCtx = manifestclient.WithControllerInstanceNameFromContext(localCtx, controllerRunner.ControllerInstanceName())
			if err := controllerRunner.RunOnce(localCtx); err != nil {
				errs = append(errs, fmt.Errorf("controller %q failed: %w", controllerRunner.ControllerInstanceName(), err))
			}
		}()
	}
	return errors.Join(errs...)
}

func (a SimpleOperatorStarter) Start(ctx context.Context) error {
	for _, informer := range a.Informers {
		informer.Start(ctx)
	}

	for _, controllerRunFn := range a.ControllerRunFns {
		go controllerRunFn(ctx)
	}
	return nil
}

type SimplifiedInformerFactory interface {
	Start(ctx context.Context)
	WaitForCacheSync(ctx context.Context)
}

type NamedRunOnce interface {
	ControllerInstanceName() string
	RunOnce(context.Context) error
}

type namedRunOnce struct {
	controllerInstanceName string
	runOnce                RunOnceFunc
}

func NewNamedRunOnce(controllerInstanceName string, runOnce RunOnceFunc) *namedRunOnce {
	return &namedRunOnce{
		controllerInstanceName: controllerInstanceName,
		runOnce:                runOnce,
	}
}

func (r *namedRunOnce) RunOnce(ctx context.Context) error {
	return r.runOnce(ctx)
}

func (r *namedRunOnce) ControllerInstanceName() string {
	return r.controllerInstanceName
}

type RunOnceFunc func(ctx context.Context) error

type RunFunc func(ctx context.Context)

type GeneratedInformerFactory interface {
	Start(stopCh <-chan struct{})
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

func GeneratedInformerFactoryAdapter(in GeneratedInformerFactory) SimplifiedInformerFactory {
	return generatedInformerFactory{delegate: in}
}

func DynamicInformerFactoryAdapter(in dynamicinformer.DynamicSharedInformerFactory) SimplifiedInformerFactory {
	return dynamicInformerFactory{delegate: in}
}

func GeneratedNamespacedInformerFactoryAdapter(in GeneratedNamespacedInformerFactory) SimplifiedInformerFactory {
	return generatedNamespacedInformerFactory{delegate: in}
}

func AdaptRunFn(fn func(ctx context.Context, workers int)) RunFunc {
	return func(ctx context.Context) {
		fn(ctx, 1)
	}
}

func AdaptSyncFn(eventRecorder events.Recorder, controllerName string, originalRunOnce func(ctx context.Context, syncCtx factory.SyncContext) error) NamedRunOnce {
	return NewNamedRunOnce(controllerName, func(ctx context.Context) error {
		syncCtx := factory.NewSyncContext("run-once-sync-context", eventRecorder)
		return originalRunOnce(ctx, syncCtx)
	})
}

type generatedInformerFactory struct {
	delegate GeneratedInformerFactory
}

func (g generatedInformerFactory) Start(ctx context.Context) {
	g.delegate.Start(ctx.Done())
}

func (g generatedInformerFactory) WaitForCacheSync(ctx context.Context) {
	g.delegate.WaitForCacheSync(ctx.Done())
}

type dynamicInformerFactory struct {
	delegate dynamicinformer.DynamicSharedInformerFactory
}

func (g dynamicInformerFactory) Start(ctx context.Context) {
	g.delegate.Start(ctx.Done())
}

func (g dynamicInformerFactory) WaitForCacheSync(ctx context.Context) {
	g.delegate.WaitForCacheSync(ctx.Done())
}

type GeneratedNamespacedInformerFactory interface {
	Start(stopCh <-chan struct{})
	WaitForCacheSync(stopCh <-chan struct{}) map[string]map[reflect.Type]bool
}

type generatedNamespacedInformerFactory struct {
	delegate GeneratedNamespacedInformerFactory
}

func (g generatedNamespacedInformerFactory) Start(ctx context.Context) {
	g.delegate.Start(ctx.Done())
}

func (g generatedNamespacedInformerFactory) WaitForCacheSync(ctx context.Context) {
	g.delegate.WaitForCacheSync(ctx.Done())
}
