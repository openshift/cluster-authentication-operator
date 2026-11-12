package common

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
)

// ServiceEndpoint is a single backend address flattened from a service's
// EndpointSlices, carrying the per-slice ports needed to build an address:port
// pair as well as the target reference used for pod health checks.
type ServiceEndpoint struct {
	Address   string
	Ready     bool
	TargetRef *corev1.ObjectReference
	Ports     []discoveryv1.EndpointPort
}

// ServiceEndpointSliceSelector selects the EndpointSlices owned by serviceName.
// Kubernetes labels every EndpointSlice it generates for a Service with
// discoveryv1.LabelServiceName.
func ServiceEndpointSliceSelector(serviceName string) labels.Selector {
	return labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: serviceName})
}

// ListServiceEndpointSlices returns all EndpointSlices associated with the named
// service. A Service may be backed by more than one EndpointSlice (for example
// one per IP family on a dual-stack cluster), so callers must aggregate across
// the returned slices.
func ListServiceEndpointSlices(lister discoveryv1listers.EndpointSliceLister, namespace, serviceName string) ([]*discoveryv1.EndpointSlice, error) {
	return lister.EndpointSlices(namespace).List(ServiceEndpointSliceSelector(serviceName))
}

// FlattenServiceEndpoints flattens the EndpointSlices of a service into a
// per-address view. Address readiness follows the EndpointSlice convention: an
// endpoint whose Ready condition is nil is treated as ready.
func FlattenServiceEndpoints(slices []*discoveryv1.EndpointSlice) []ServiceEndpoint {
	var result []ServiceEndpoint
	for _, slice := range slices {
		for i := range slice.Endpoints {
			endpoint := &slice.Endpoints[i]
			ready := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
			for _, address := range endpoint.Addresses {
				result = append(result, ServiceEndpoint{
					Address:   address,
					Ready:     ready,
					TargetRef: endpoint.TargetRef,
					Ports:     slice.Ports,
				})
			}
		}
	}
	return result
}

// CountReadyBackends counts the distinct ready backends across the given
// endpoints, deduplicating by target reference (falling back to the address)
// so that a backend reported in multiple slices (e.g. its IPv4 and IPv6
// addresses on a dual-stack cluster) is only counted once.
func CountReadyBackends(endpoints []ServiceEndpoint) int {
	seen := sets.New[string]()
	for _, endpoint := range endpoints {
		if !endpoint.Ready {
			continue
		}
		key := endpoint.Address
		if ref := endpoint.TargetRef; ref != nil {
			if len(ref.UID) > 0 {
				key = string(ref.UID)
			} else {
				key = ref.Namespace + "/" + ref.Name
			}
		}
		seen.Insert(key)
	}
	return seen.Len()
}
