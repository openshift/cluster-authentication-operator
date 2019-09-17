package operator2

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_authOperator_handleConfigResourceVersions(t *testing.T) {
	tests := []struct {
		name    string
		objects []runtime.Object
		want    []string
	}{
		{
			name:    "none",
			objects: nil,
			want:    nil,
		},
		{
			name: "ignored",
			objects: []runtime.Object{
				testRVSecret("a", "1"),
				testRVConfigMap("b", "2"),
			},
			want: nil,
		},
		{
			name: "user config only",
			objects: []runtime.Object{
				testRVSecret("v4-0-config-user-a", "1"),
				testRVConfigMap("v4-0-config-user-b", "2"),
			},
			want: []string{
				testRVString("configmaps", "v4-0-config-user-b", "2"),
				testRVString("secrets", "v4-0-config-user-a", "1"),
			},
		},
		{
			name: "system config only",
			objects: []runtime.Object{
				testRVSecret("v4-0-config-system-c", "3"),
				testRVConfigMap("v4-0-config-system-d", "4"),
			},
			want: []string{
				testRVString("configmaps", "v4-0-config-system-d", "4"),
				testRVString("secrets", "v4-0-config-system-c", "3"),
			},
		},
		{
			name: "both config",
			objects: []runtime.Object{
				testRVSecret("v4-0-config-user-a", "1"),
				testRVConfigMap("v4-0-config-user-b", "2"),
				testRVSecret("v4-0-config-system-c", "3"),
				testRVConfigMap("v4-0-config-system-d", "4"),
			},
			want: []string{
				testRVString("configmaps", "v4-0-config-user-b", "2"),
				testRVString("configmaps", "v4-0-config-system-d", "4"),
				testRVString("secrets", "v4-0-config-user-a", "1"),
				testRVString("secrets", "v4-0-config-system-c", "3"),
			},
		},
		{
			name: "both config overlapping resource versions",
			objects: []runtime.Object{
				testRVSecret("v4-0-config-user-a", "1"),
				testRVConfigMap("v4-0-config-user-b", "2"),
				testRVSecret("v4-0-config-system-c", "2"),
				testRVConfigMap("v4-0-config-system-d", "1"),
			},
			want: []string{
				testRVString("configmaps", "v4-0-config-user-b", "2"),
				testRVString("configmaps", "v4-0-config-system-d", "1"),
				testRVString("secrets", "v4-0-config-user-a", "1"),
				testRVString("secrets", "v4-0-config-system-c", "2"),
			},
		},
		{
			name: "both config overlapping resource versions and ignored data",
			objects: []runtime.Object{
				testRVSecret("e", "5"),
				testRVConfigMap("f", "6"),
				testRVSecret("v4-0-config-user-a", "3"),
				testRVConfigMap("v4-0-config-user-b", "2"),
				testRVSecret("v4-0-config-system-c", "2"),
				testRVConfigMap("v4-0-config-system-d", "3"),
			},
			want: []string{
				testRVString("configmaps", "v4-0-config-user-b", "2"),
				testRVString("configmaps", "v4-0-config-system-d", "3"),
				testRVString("secrets", "v4-0-config-user-a", "3"),
				testRVString("secrets", "v4-0-config-system-c", "2"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			c := &authOperator{
				secrets:    client.CoreV1(),
				configMaps: client.CoreV1(),
			}
			got, err := c.handleConfigResourceVersions()
			if err != nil {
				t.Errorf("handleConfigResourceVersions() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("handleConfigResourceVersions() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func testRVSecret(name, rv string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       "openshift-authentication",
			ResourceVersion: rv,
		},
	}
}

func testRVConfigMap(name, rv string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       "openshift-authentication",
			ResourceVersion: rv,
		},
	}
}

func testRVString(prefix, name, rv string) string {
	return prefix + ":" + name + ":" + rv
}
