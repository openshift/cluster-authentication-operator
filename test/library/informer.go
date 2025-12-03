package library

import (
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/client-go/tools/cache"
)

type FakeSharedIndexInformerWithSync[T any] struct {
	lister    T
	hasSynced bool
}

func NewFakeSharedIndexInformerWithSync[T any](lister T, hasSynced bool) *FakeSharedIndexInformerWithSync[T] {
	return &FakeSharedIndexInformerWithSync[T]{
		lister:    lister,
		hasSynced: hasSynced,
	}
}

func (f *FakeSharedIndexInformerWithSync[T]) Informer() cache.SharedIndexInformer {
	return &fakeSharedIndexInformer{
		SharedIndexInformer: v1helpers.NewFakeSharedIndexInformer(),
		hasSynced:           f.hasSynced,
	}
}

func (f *FakeSharedIndexInformerWithSync[T]) Lister() T {
	return f.lister
}

type fakeSharedIndexInformer struct {
	cache.SharedIndexInformer
	hasSynced bool
}

func (f *fakeSharedIndexInformer) HasSynced() bool {
	return f.hasSynced
}
