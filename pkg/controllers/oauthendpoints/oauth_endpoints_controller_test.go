package oauthendpoints

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

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
