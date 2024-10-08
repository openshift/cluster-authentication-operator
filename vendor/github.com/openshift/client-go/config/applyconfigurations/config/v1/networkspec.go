// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// NetworkSpecApplyConfiguration represents a declarative configuration of the NetworkSpec type for use
// with apply.
type NetworkSpecApplyConfiguration struct {
	ClusterNetwork       []ClusterNetworkEntryApplyConfiguration `json:"clusterNetwork,omitempty"`
	ServiceNetwork       []string                                `json:"serviceNetwork,omitempty"`
	NetworkType          *string                                 `json:"networkType,omitempty"`
	ExternalIP           *ExternalIPConfigApplyConfiguration     `json:"externalIP,omitempty"`
	ServiceNodePortRange *string                                 `json:"serviceNodePortRange,omitempty"`
	NetworkDiagnostics   *NetworkDiagnosticsApplyConfiguration   `json:"networkDiagnostics,omitempty"`
}

// NetworkSpecApplyConfiguration constructs a declarative configuration of the NetworkSpec type for use with
// apply.
func NetworkSpec() *NetworkSpecApplyConfiguration {
	return &NetworkSpecApplyConfiguration{}
}

// WithClusterNetwork adds the given value to the ClusterNetwork field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ClusterNetwork field.
func (b *NetworkSpecApplyConfiguration) WithClusterNetwork(values ...*ClusterNetworkEntryApplyConfiguration) *NetworkSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithClusterNetwork")
		}
		b.ClusterNetwork = append(b.ClusterNetwork, *values[i])
	}
	return b
}

// WithServiceNetwork adds the given value to the ServiceNetwork field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ServiceNetwork field.
func (b *NetworkSpecApplyConfiguration) WithServiceNetwork(values ...string) *NetworkSpecApplyConfiguration {
	for i := range values {
		b.ServiceNetwork = append(b.ServiceNetwork, values[i])
	}
	return b
}

// WithNetworkType sets the NetworkType field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NetworkType field is set to the value of the last call.
func (b *NetworkSpecApplyConfiguration) WithNetworkType(value string) *NetworkSpecApplyConfiguration {
	b.NetworkType = &value
	return b
}

// WithExternalIP sets the ExternalIP field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ExternalIP field is set to the value of the last call.
func (b *NetworkSpecApplyConfiguration) WithExternalIP(value *ExternalIPConfigApplyConfiguration) *NetworkSpecApplyConfiguration {
	b.ExternalIP = value
	return b
}

// WithServiceNodePortRange sets the ServiceNodePortRange field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceNodePortRange field is set to the value of the last call.
func (b *NetworkSpecApplyConfiguration) WithServiceNodePortRange(value string) *NetworkSpecApplyConfiguration {
	b.ServiceNodePortRange = &value
	return b
}

// WithNetworkDiagnostics sets the NetworkDiagnostics field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NetworkDiagnostics field is set to the value of the last call.
func (b *NetworkSpecApplyConfiguration) WithNetworkDiagnostics(value *NetworkDiagnosticsApplyConfiguration) *NetworkSpecApplyConfiguration {
	b.NetworkDiagnostics = value
	return b
}
