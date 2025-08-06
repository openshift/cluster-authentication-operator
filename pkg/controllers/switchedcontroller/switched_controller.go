package switchedcontroller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type ControllerWithSwitch struct {
	delegateName      string
	delegateFactoryFn DelegateFactoryFunc

	switchConditionFn   DelegateSwitchCondition
	switchContext       context.Context
	switchContextCancel context.CancelFunc

	mutex sync.Mutex
}

// DelegateSwitchCondition defines a condition function that controls when the delegate
// controller must be switched on or off.
type DelegateSwitchCondition func() (bool, error)

// DelegateFactoryFunc returns a controller factory that can be used to create an instance
// of the delegate controller. The SwitchedController's context is passed to the function
// so that it may be used to start any informers that also depend on the DelegateSwitchCondition.
// This context is cancelled when DelegateSwitchCondition returns (false, nil).
type DelegateFactoryFunc func(context.Context) *factory.Factory

// NewControllerWithSwitch creates an instance of a switched controller. The switched controller is
// defined by the following:
// - delegateFactoryFn: a function that is invoked when a new instance of the delegate controller must be created
// - switchConditionFn: a function that is invoked on every switched controller sync to determine whether it needs to switch on/off the delegate controller
// - informers: any informers that must be tracked and are required by the switch condition
//
// If no delegateFactoryFn is defined, the controller's sync will always fail. If no switchConditionFn is defined,
// the delegate controller will never be switched off.
func NewControllerWithSwitch(
	operatorClient v1helpers.OperatorClient,
	delegateName string,
	delegateFactoryFn DelegateFactoryFunc,
	switchConditionFn DelegateSwitchCondition,
	informers []factory.Informer,
	resyncInterval time.Duration,
	eventRecorder events.Recorder,
) factory.Controller {

	if delegateFactoryFn == nil {
		panic(fmt.Errorf("no delegate factory function defined for '%s'", delegateName))
	}

	if switchConditionFn == nil {
		panic(fmt.Errorf("no switch condition defined for '%s'", delegateName))
	}

	c := &ControllerWithSwitch{
		delegateName:      delegateName,
		delegateFactoryFn: delegateFactoryFn,
		switchConditionFn: switchConditionFn,
	}

	return factory.New().
		WithSync(c.sync).
		WithSyncDegradedOnError(operatorClient).
		WithInformers(informers...).
		ResyncEvery(resyncInterval).
		ToController(delegateName+"_SwitchedController", eventRecorder)
}

func (c *ControllerWithSwitch) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	switchOn, err := c.switchConditionFn()
	if err != nil {
		return fmt.Errorf("could not determine switch condition: %v", err)
	}

	noContext := c.switchContext == nil
	contextDone := (c.switchContext != nil) && (c.switchContext.Err() != nil)
	contextActive := (c.switchContext != nil) && (c.switchContext.Err() == nil)

	switch {
	case switchOn && (noContext || contextDone):
		// we've been asked to start a context/delegate and there is either no active context/delegate, or
		// context has been cancelled externally; delegate will shut down eventually
		c.mutex.Lock()
		c.switchContext, c.switchContextCancel = context.WithCancel(ctx)
		go c.delegateFactoryFn(c.switchContext).ToController(c.delegateName, syncCtx.Recorder()).Run(c.switchContext, 1)
		c.mutex.Unlock()

	case switchOn && contextActive:
		// delegate is running; nothing to do

	case !switchOn && (noContext || contextDone):
		// we haven't been asked to start yet, or
		// context has been cancelled externally; delegate will shut down eventually

	case !switchOn && contextActive:
		// we've been asked to shut down the context/delegate
		c.mutex.Lock()
		c.switchContextCancel()
		c.switchContext = nil
		c.mutex.Unlock()

	default:
		var e error
		c.mutex.Lock()
		if c.switchContext != nil {
			e = c.switchContext.Err()
		}
		e = fmt.Errorf("this should never happen; switchOn = %v; switchContext == nil? %t; switchContext error = %v", switchOn, c.switchContext == nil, e)
		c.mutex.Unlock()
		return e
	}

	return nil
}
