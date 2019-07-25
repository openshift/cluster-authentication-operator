package operator

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"monis.app/go/openshift/controller"
)

type Option func(*operator)

func WithInformer(getter controller.InformerGetter, filter controller.Filter, opts ...controller.InformerOption) Option {
	return func(o *operator) {
		o.opts = append(o.opts,
			controller.WithInformer(getter, controller.FilterFuncs{
				ParentFunc: func(obj v1.Object) (namespace, name string) {
					return o.name, o.name // return our singleton key for all events
				},
				AddFunc:    filter.Add,
				UpdateFunc: filter.Update,
				DeleteFunc: filter.Delete,
			}, opts...),
		)
	}
}

func WithRealInformer(informer cache.SharedIndexInformer, filter controller.Filter) Option {
	return func(o *operator) {
		o.opts = append(o.opts,
			controller.WithRealInformer(informer, controller.FilterFuncs{
				ParentFunc: func(obj v1.Object) (namespace, name string) {
					return o.name, o.name // return our singleton key for all events
				},
				AddFunc:    filter.Add,
				UpdateFunc: filter.Update,
				DeleteFunc: filter.Delete,
			}),
		)
	}
}
