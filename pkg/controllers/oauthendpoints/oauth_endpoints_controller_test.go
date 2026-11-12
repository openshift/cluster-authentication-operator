package oauthendpoints

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1lister "github.com/openshift/client-go/config/listers/config/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
)

func Test_toHealthzURL(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "test urls",
			args: []string{"a", "b"},
			want: []string{"https://a/healthz", "https://b/healthz"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toHealthzURL(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toHealthzURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_listOAuthRoutes(t *testing.T) {
	tests := []struct {
		name          string
		ingressConfig *configv1.Ingress
		route         *routev1.Route
		want          []string
		wantErr       bool
	}{
		{
			name:          "no route",
			ingressConfig: authIngressConfig("hostname.one"),
			wantErr:       true,
		},
		{
			name:    "no ingress config",
			route:   authRoute("hostname.one"),
			wantErr: true,
		},
		{
			name:  "no ingress config status",
			route: authRoute("hostname.one"),
			ingressConfig: &configv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
			},
			wantErr: true,
		},
		{
			name:          "no admitted ingress in route",
			ingressConfig: authIngressConfig("hostname.one"),
			route:         authRoute(),
			wantErr:       true,
		},
		{
			name:          "admitted ingress in route different than the one in config",
			ingressConfig: authIngressConfig("hostname.one"),
			route:         authRoute("hostname.two"),
			wantErr:       true,
		},
		{
			name:          "admitted ingress from config among other admitted ingresses",
			ingressConfig: authIngressConfig("hostname.one"),
			route:         authRoute("hostname.two", "hostname.tree", "hostname.one", "hostname.four"),
			want:          []string{"https://hostname.one/healthz"},
		},
		{
			name:          "multiple current hostnames, not all admitted yet",
			ingressConfig: authIngressConfig("hostname.one", "hostname.five"),
			route:         authRoute("hostname.two", "hostname.tree", "hostname.one", "hostname.four"),
			wantErr:       true,
		},
		{
			name:          "multiple current hostnames, all admitted already",
			ingressConfig: authIngressConfig("hostname.one", "hostname.two"),
			route:         authRoute("hostname.two", "hostname.tree", "hostname.one", "hostname.four"),
			want:          []string{"https://hostname.two/healthz", "https://hostname.one/healthz"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			ingresses := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.ingressConfig != nil {
				require.NoError(t, ingresses.Add(tt.ingressConfig))
			}
			if tt.route != nil {
				require.NoError(t, routes.Add(tt.route))
			}

			got, err := listOAuthRoutes(configv1lister.NewIngressLister(ingresses), routev1listers.NewRouteLister(routes))
			if (err != nil) != tt.wantErr {
				t.Errorf("listOAuthRoutes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("listOAuthRoutes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func oauthEndpointSlice(name string, port int32, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-authentication",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "oauth-openshift"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports: []discoveryv1.EndpointPort{
			{Port: ptr.To(port), Protocol: ptr.To(corev1.ProtocolTCP)},
		},
	}
}

func Test_listOAuthServiceEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		slices  []*discoveryv1.EndpointSlice
		want    []string
		wantErr bool
	}{
		{
			name:    "no endpointslices",
			wantErr: true,
		},
		{
			name: "no ready endpoints",
			slices: []*discoveryv1.EndpointSlice{
				oauthEndpointSlice("oauth-openshift-1", 6443, discoveryv1.Endpoint{
					Addresses:  []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
				}),
			},
			wantErr: true,
		},
		{
			name: "ready endpoints aggregated across slices, not-ready excluded",
			slices: []*discoveryv1.EndpointSlice{
				oauthEndpointSlice("oauth-openshift-1", 6443,
					discoveryv1.Endpoint{
						Addresses:  []string{"10.0.0.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
					},
					discoveryv1.Endpoint{
						Addresses:  []string{"10.0.0.2"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
					},
				),
				oauthEndpointSlice("oauth-openshift-2", 6443, discoveryv1.Endpoint{
					Addresses:  []string{"10.0.0.3"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				}),
			},
			want: []string{"https://10.0.0.1:6443/healthz", "https://10.0.0.3:6443/healthz"},
		},
		{
			// An endpoint with a nil Ready condition follows the EndpointSlice
			// convention and is treated as ready.
			name: "nil ready condition is treated as ready",
			slices: []*discoveryv1.EndpointSlice{
				oauthEndpointSlice("oauth-openshift-1", 6443, discoveryv1.Endpoint{
					Addresses:  []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: nil},
				}),
			},
			want: []string{"https://10.0.0.1:6443/healthz"},
		},
		{
			// A slice may advertise a port with a nil number; such ports are
			// skipped while numbered ports on the same slice are still used.
			name: "nil port is skipped alongside a numbered port",
			slices: []*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-openshift-1",
						Namespace: "openshift-authentication",
						Labels:    map[string]string{discoveryv1.LabelServiceName: "oauth-openshift"},
					},
					AddressType: discoveryv1.AddressTypeIPv4,
					Endpoints: []discoveryv1.Endpoint{{
						Addresses:  []string{"10.0.0.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
					}},
					Ports: []discoveryv1.EndpointPort{
						{Port: nil, Protocol: ptr.To(corev1.ProtocolTCP)},
						{Port: ptr.To(int32(6443)), Protocol: ptr.To(corev1.ProtocolTCP)},
					},
				},
			},
			want: []string{"https://10.0.0.1:6443/healthz"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, slice := range tt.slices {
				require.NoError(t, indexer.Add(slice))
			}

			got, err := listOAuthServiceEndpoints(discoveryv1listers.NewEndpointSliceLister(indexer))
			if (err != nil) != tt.wantErr {
				t.Fatalf("listOAuthServiceEndpoints() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func authRoute(admittedIngressHostnames ...string) *routev1.Route {
	r := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-authentication",
			Name:      "oauth-openshift",
		},
	}

	for _, host := range admittedIngressHostnames {
		r.Status.Ingress = append(r.Status.Ingress,
			routev1.RouteIngress{
				Host: host,
				Conditions: []routev1.RouteIngressCondition{
					{
						Type:   routev1.RouteAdmitted,
						Status: corev1.ConditionTrue,
					},
				},
			})
	}

	return r
}

func authIngressConfig(currentHostnames ...configv1.Hostname) *configv1.Ingress {
	return &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.IngressStatus{
			ComponentRoutes: []configv1.ComponentRouteStatus{
				{
					Namespace:        "openshift-authentication",
					Name:             "oauth-openshift",
					CurrentHostnames: currentHostnames,
				},
			},
		},
	}
}
