package libraryapplyconfiguration

import (
	"context"
	"errors"
	"reflect"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

type OperatorStarter interface {
	RunOnce(ctx context.Context) error
	Start(ctx context.Context) error
}

type SimpleOperatorStarter struct {
	Informers            []SimplifiedInformerFactory
	ControllerRunOnceFns []RunOnceFunc
	// ControllerRunFns is useful during a transition to coalesce the operator launching flow.
	ControllerRunFns []RunFunc
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
	// wait for sync so that when RunOnce is called the listers will be ready.
	// TODO add timeout
	for _, informer := range a.Informers {
		informer.WaitForCacheSync(ctx)
	}

	errs := []error{}

	for _, controllerRunOnceFn := range a.ControllerRunOnceFns {
		// TODO add timeout.
		err := controllerRunOnceFn(ctx)
		errs = append(errs, err)
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

func AdaptSyncFn(eventRecorder events.Recorder, originalRunOnce func(ctx context.Context, syncCtx factory.SyncContext) error) RunOnceFunc {
	return func(ctx context.Context) error {
		syncCtx := factory.NewSyncContext("run-once-sync-context", eventRecorder)
		return originalRunOnce(ctx, syncCtx)
	}
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
