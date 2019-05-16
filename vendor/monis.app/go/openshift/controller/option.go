package controller

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

type Option func(*controller)

type InformerGetter interface {
	Informer() cache.SharedIndexInformer
}

func WithMaxRetries(maxRetries int) Option {
	return func(c *controller) {
		c.maxRetries = maxRetries
	}
}

func WithInitialEvent(namespace, name string) Option {
	return toNaiveRunOpt(func(c *controller) {
		c.addKey(namespace, name)
	})
}

func WithRateLimiter(limiter workqueue.RateLimiter) Option {
	return func(c *controller) {
		c.queue = workqueue.NewNamedRateLimitingQueue(limiter, c.name)
	}
}

func WithInformerSynced(getter InformerGetter) Option {
	informer := getter.Informer() // immediately signal that we intend to use this informer in case it is lazily initialized
	return toRunOpt(func(c *controller) {
		c.cacheSyncs = append(c.cacheSyncs, informer.GetController().HasSynced)
	})
}

func WithInformer(getter InformerGetter, filter ParentFilter, opts ...InformerOption) Option {
	informer := getter.Informer() // immediately signal that we intend to use this informer in case it is lazily initialized
	return toRunOpt(func(c *controller) {
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				object := metaOrDie(obj)
				if filter.Add(object) {
					klog.V(4).Infof("%s: handling add %s/%s: %s", c.name, object.GetNamespace(), object.GetName(), object.GetSelfLink())
					c.add(filter, object)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldObject := metaOrDie(oldObj)
				newObject := metaOrDie(newObj)
				if filter.Update(oldObject, newObject) {
					klog.V(4).Infof("%s: handling update %s/%s: %s", c.name, newObject.GetNamespace(), newObject.GetName(), newObject.GetSelfLink())
					c.add(filter, newObject)
				}
			},
			DeleteFunc: func(obj interface{}) {
				accessor, err := meta.Accessor(obj)
				if err != nil {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						utilruntime.HandleError(fmt.Errorf("could not get object from tombstone: %+v", obj))
						return
					}
					accessor, err = meta.Accessor(tombstone.Obj)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not an accessor: %+v", obj))
						return
					}
				}
				if filter.Delete(accessor) {
					klog.V(4).Infof("%s: handling delete %s/%s: %s", c.name, accessor.GetNamespace(), accessor.GetName(), accessor.GetSelfLink())
					c.add(filter, accessor)
				}
			},
		})

		// default to a safe sync setting
		if len(opts) == 0 {
			opts = []InformerOption{withSync()}
		}

		for _, opt := range opts {
			informerOptionToOption(opt, getter)(c)
		}
	})
}

func toRunOpt(opt Option) Option {
	return toOnceOpt(toNaiveRunOpt(opt))
}

func toNaiveRunOpt(opt Option) Option {
	return func(c *controller) {
		if c.run {
			opt(c)
			return
		}
		c.runOpts = append(c.runOpts, opt)
	}
}

func toOnceOpt(opt Option) Option {
	var once sync.Once
	return func(c *controller) {
		once.Do(func() {
			opt(c)
		})
	}
}

func metaOrDie(obj interface{}) v1.Object {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		panic(err) // this should never happen
	}
	return accessor
}
