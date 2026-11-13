package common

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/internal/transporttest"
)

var (
	enabledAuthProxy  = func() (bool, error) { return true, nil }
	disabledAuthProxy = func() (bool, error) { return false, nil }
)

func TestResolveProxy(t *testing.T) {
	const failingEnabledErrMsg = "not yet observed"
	failingEnabled := func() (bool, error) { return false, errors.New(failingEnabledErrMsg) }

	proxySet := &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: operatorv1.AuthenticationSpec{
			Proxy: operatorv1.AuthenticationProxyConfig{
				HTTPSProxy: "http://proxy:3128",
				TrustedCA:  operatorv1.AuthenticationConfigMapReference{Name: "my-ca-bundle"},
			},
		},
	}
	proxyEmpty := &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}

	tests := []struct {
		name       string
		enabled    func() (bool, error)
		lister     operatorv1listers.AuthenticationLister
		envHTTP    string
		envHTTPS   string
		envNoProxy string
		want       ResolvedProxy
		wantErr    string
	}{
		{
			name:    "gate disabled falls back to env",
			enabled: disabledAuthProxy,
			lister:  newOperatorAuthLister(proxySet),
			envHTTP: "http://cluster:3128",
			want:    ResolvedProxy{HTTPProxy: "http://cluster:3128"},
		},
		{
			name:    "enabled callback error propagates",
			enabled: failingEnabled,
			lister:  newOperatorAuthLister(proxySet),
			wantErr: failingEnabledErrMsg,
		},
		{
			name:    "lister error propagates",
			enabled: enabledAuthProxy,
			lister:  newErrorAuthLister(errors.New("connection refused")),
			wantErr: "failed to get operator.openshift.io/v1 authentication/cluster: connection refused",
		},
		{
			name:     "CR not found falls back to env",
			enabled:  enabledAuthProxy,
			lister:   newOperatorAuthLister(nil),
			envHTTPS: "http://cluster:3129",
			want:     ResolvedProxy{HTTPSProxy: "http://cluster:3129"},
		},
		{
			name:    "CR exists but proxy is zero-value falls back to env",
			enabled: enabledAuthProxy,
			lister:  newOperatorAuthLister(proxyEmpty),
			want:    ResolvedProxy{},
		},
		{
			name:    "component proxy set returns active proxy with trustedCA",
			enabled: enabledAuthProxy,
			lister:  newOperatorAuthLister(proxySet),
			envHTTP: "http://should-be-ignored:3128",
			want: ResolvedProxy{
				TrustedCAName: "my-ca-bundle",
				HTTPSProxy:    "http://proxy:3128",
				NoProxy:       expectedNoProxy(),
			},
		},
		{
			name:    "component proxy with user noProxy merges with defaults",
			enabled: enabledAuthProxy,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://component:3128",
						NoProxy:   []string{"idp.example.com", ".corp.example.com"},
					},
				},
			}),
			want: ResolvedProxy{
				HTTPProxy: "http://component:3128",
				NoProxy:   expectedNoProxy("idp.example.com", ".corp.example.com"),
			},
		},
		{
			name:    "component proxy with user noProxy duplicating defaults deduplicates",
			enabled: enabledAuthProxy,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://component:3128",
						NoProxy:   []string{".svc", "idp.example.com", "127.0.0.1"},
					},
				},
			}),
			want: ResolvedProxy{
				HTTPProxy: "http://component:3128",
				NoProxy:   expectedNoProxy("idp.example.com"),
			},
		},
		{
			name:    "component proxy with only httpsProxy overrides env",
			enabled: enabledAuthProxy,
			lister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://component:3129",
					},
				},
			}),
			envHTTP:  "http://cluster:3128",
			envHTTPS: "http://cluster:3129",
			want: ResolvedProxy{
				HTTPSProxy: "http://component:3129",
				NoProxy:    expectedNoProxy(),
			},
		},
		{
			name:    "neither configured returns empty",
			enabled: disabledAuthProxy,
			lister:  newOperatorAuthLister(nil),
			want:    ResolvedProxy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", tt.envHTTP)
			t.Setenv("HTTPS_PROXY", tt.envHTTPS)
			t.Setenv("NO_PROXY", tt.envNoProxy)

			got, err := ResolveProxy(tt.enabled, tt.lister)

			var errMsg string
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != tt.wantErr {
				t.Fatalf("error = %q, want %q", errMsg, tt.wantErr)
			}
			if tt.wantErr != "" {
				return
			}

			if got.HTTPProxy != tt.want.HTTPProxy {
				t.Errorf("HTTPProxy = %q, want %q", got.HTTPProxy, tt.want.HTTPProxy)
			}
			if got.HTTPSProxy != tt.want.HTTPSProxy {
				t.Errorf("HTTPSProxy = %q, want %q", got.HTTPSProxy, tt.want.HTTPSProxy)
			}
			if got.NoProxy != tt.want.NoProxy {
				t.Errorf("NoProxy = %q, want %q", got.NoProxy, tt.want.NoProxy)
			}
			if got.TrustedCAName != tt.want.TrustedCAName {
				t.Errorf("TrustedCAName = %q, want %q", got.TrustedCAName, tt.want.TrustedCAName)
			}
		})
	}
}

func TestResolvedProxy_IsProxyConfigured(t *testing.T) {
	tests := []struct {
		name  string
		proxy ResolvedProxy
		want  bool
	}{
		{
			name:  "both empty",
			proxy: ResolvedProxy{},
			want:  false,
		},
		{
			name:  "http proxy set",
			proxy: ResolvedProxy{HTTPProxy: "http://proxy:3128"},
			want:  true,
		},
		{
			name:  "https proxy set",
			proxy: ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
			want:  true,
		},
		{
			name:  "both set",
			proxy: ResolvedProxy{HTTPProxy: "http://proxy:3128", HTTPSProxy: "http://proxy:3129"},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.proxy.IsProxyConfigured(); got != tt.want {
				t.Errorf("IsProxyConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolvedProxy_ProxyFunc(t *testing.T) {
	httpsURL := transporttest.MustParseURL(t, "https://idp.example.com/.well-known/openid-configuration")
	httpURL := transporttest.MustParseURL(t, "http://idp.example.com/callback")

	tests := []struct {
		name         string
		enabled      func() (bool, error)
		authLister   operatorv1listers.AuthenticationLister
		reqURL       *url.URL
		wantProxyURL string
	}{
		{
			name:    "feature gate disabled returns nil proxy (no env)",
			enabled: disabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://should-not-be-used:3128",
					},
				},
			}),
			reqURL: httpsURL,
		},
		{
			name:    "feature gate enabled but no proxy configured returns nil proxy (no env)",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			}),
			reqURL: httpsURL,
		},
		{
			name:    "feature gate enabled with httpsProxy configured returns proxy for https request",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL:       httpsURL,
			wantProxyURL: "http://proxy.corp.example.com:3128",
		},
		{
			name:    "feature gate enabled with httpProxy configured returns proxy for http request",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL:       httpURL,
			wantProxyURL: "http://proxy.corp.example.com:3128",
		},
		{
			name:    "httpsProxy configured does not proxy http requests",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL: httpURL,
		},
		{
			name:    "httpProxy configured does not proxy https requests",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPProxy: "http://proxy.corp.example.com:3128",
					},
				},
			}),
			reqURL: httpsURL,
		},
		{
			name:    "noProxy match returns nil proxy",
			enabled: enabledAuthProxy,
			authLister: newOperatorAuthLister(&operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: operatorv1.AuthenticationSpec{
					Proxy: operatorv1.AuthenticationProxyConfig{
						HTTPSProxy: "http://proxy.corp.example.com:3128",
						NoProxy:    []string{httpURL.Host},
					},
				},
			}),
			reqURL: httpsURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("NO_PROXY", "")

			proxy, err := ResolveProxy(tt.enabled, tt.authLister)
			if err != nil {
				t.Fatalf("unexpected resolve error: %v", err)
			}
			proxyURL, err := proxy.ProxyFunc()(tt.reqURL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var gotProxyURL string
			if proxyURL != nil {
				gotProxyURL = proxyURL.String()
			}
			if gotProxyURL != tt.wantProxyURL {
				t.Errorf("proxy URL = %q, want %q", gotProxyURL, tt.wantProxyURL)
			}
		})
	}
}

func TestProxyEnvVars(t *testing.T) {
	tests := []struct {
		name                           string
		httpProxy, httpsProxy, noProxy string
		want                           []corev1.EnvVar
	}{
		{
			name:       "all proxy values",
			httpProxy:  "http://proxy.example.com:8080",
			httpsProxy: "https://proxy.example.com:8443",
			noProxy:    ".svc,localhost",
			want: []corev1.EnvVar{
				{Name: "NO_PROXY", Value: ".svc,localhost"},
				{Name: "HTTP_PROXY", Value: "http://proxy.example.com:8080"},
				{Name: "HTTPS_PROXY", Value: "https://proxy.example.com:8443"},
			},
		},
		{name: "empty proxy values"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, ProxyEnvVars(tt.httpProxy, tt.httpsProxy, tt.noProxy)); diff != "" {
				t.Fatalf("unexpected proxy environment variables (-want +got):\n%s", diff)
			}
		})
	}
}

func newOperatorAuthLister(auth *operatorv1.Authentication) operatorv1listers.AuthenticationLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if auth != nil {
		_ = indexer.Add(auth)
	}
	return operatorv1listers.NewAuthenticationLister(indexer)
}

type errorAuthLister struct {
	err error
}

func newErrorAuthLister(err error) operatorv1listers.AuthenticationLister {
	return &errorAuthLister{err}
}

func (l *errorAuthLister) List(_ labels.Selector) ([]*operatorv1.Authentication, error) {
	return nil, l.err
}

func (l *errorAuthLister) Get(_ string) (*operatorv1.Authentication, error) {
	return nil, l.err
}

func expectedNoProxy(extra ...string) string {
	entries := sets.New[string](".cluster.local", ".svc", "127.0.0.1", "localhost")
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		entries.Insert(host)
	}
	entries.Insert(extra...)
	return strings.Join(sets.List(entries), ",")
}

func TestDeploymentRolledOutWithVolume(t *testing.T) {
	const (
		volumeName    = "test-volume"
		containerName = "c"
	)

	// newDeployment returns a fully rolled out 3-replica deployment mounting the volume.
	newDeployment := func(mutate func(d *appsv1.Deployment)) *appsv1.Deployment {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Spec: appsv1.DeploymentSpec{
				Replicas: new(int32(3)),
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{Name: volumeName}},
					Containers: []corev1.Container{{
						Name:         containerName,
						VolumeMounts: []corev1.VolumeMount{{Name: volumeName}},
					}},
				}},
			},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 3, UpdatedReplicas: 3},
		}
		if mutate != nil {
			mutate(d)
		}
		return d
	}

	for _, tt := range []struct {
		name     string
		dep      *appsv1.Deployment
		expected bool
	}{
		{name: "nil deployment", dep: nil, expected: false},
		{name: "fully rolled out", dep: newDeployment(nil), expected: true},
		{
			name:     "ready/available counts are not required",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Status.ReadyReplicas, d.Status.AvailableReplicas = 0, 0 }),
			expected: true,
		},
		{
			name:     "nil spec replicas defaults to 1",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Spec.Replicas = nil; d.Status.Replicas, d.Status.UpdatedReplicas = 1, 1 }),
			expected: true,
		},
		{
			name:     "generation not yet observed",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 1 }),
			expected: false,
		},
		{
			name:     "volume missing",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Spec.Template.Spec.Volumes = nil }),
			expected: false,
		},
		{
			name:     "volume declared but not mounted",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].VolumeMounts = nil }),
			expected: false,
		},
		{
			name: "volume mounted only by a different container",
			dep: newDeployment(func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers = []corev1.Container{
					{Name: "other"},
					{Name: containerName, VolumeMounts: []corev1.VolumeMount{{Name: volumeName}}},
				}
			}),
			expected: true,
		},
		{
			name: "named container missing",
			dep: newDeployment(func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers[0].Name = "other"
			}),
			expected: false,
		},
		{
			name:     "no containers",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers = nil }),
			expected: false,
		},
		{
			name:     "not all replicas updated",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 2 }),
			expected: false,
		},
		{
			name:     "old replicas still present",
			dep:      newDeployment(func(d *appsv1.Deployment) { d.Status.Replicas = 4 }),
			expected: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeploymentRolledOutWithVolume(tt.dep, containerName, volumeName); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
