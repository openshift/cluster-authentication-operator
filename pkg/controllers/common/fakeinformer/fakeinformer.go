package fakeinformer

import (
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"k8s.io/client-go/tools/cache"
)

// Authentication is a test helper implementing
// operatorv1informers.AuthenticationInformer backed by a manually created lister.
type Authentication struct {
	AuthLister operatorv1listers.AuthenticationLister
}

func (f *Authentication) Informer() cache.SharedIndexInformer            { return nil }
func (f *Authentication) Lister() operatorv1listers.AuthenticationLister { return f.AuthLister }
