package library

import (
	"k8s.io/client-go/tools/cache"
)

func NewFakeInformer[T any](lister T) *FakeInformer[T] {
	return &FakeInformer[T]{lister}
}

type FakeInformer[T any] struct {
	lister T
}

func (f *FakeInformer[T]) Informer() cache.SharedIndexInformer {
	return nil
}

func (f *FakeInformer[T]) Lister() T {
	return f.lister
}
