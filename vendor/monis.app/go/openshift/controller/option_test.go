package controller

import (
	"testing"

	"k8s.io/client-go/tools/cache"
)

type getter bool

func (g *getter) Informer() cache.SharedIndexInformer {
	*g = true
	return nil
}

func TestInformerCalled(t *testing.T) {
	g := getter(false)
	_ = New("", nil, WithInformer(&g, FilterByNames(nil)))
	if !g {
		t.Error("expected InformerGetter.Informer() to be called")
	}
}
