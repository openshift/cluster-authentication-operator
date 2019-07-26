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
				testRVSecret(userConfigPrefix+"a", "1"),
				testRVConfigMap(userConfigPrefix+"b", "2"),
			},
			want: []string{"configmaps:2", "secrets:1"},
		},
		{
			name: "system config only",
			objects: []runtime.Object{
				testRVSecret(systemConfigPrefix+"c", "3"),
				testRVConfigMap(systemConfigPrefix+"d", "4"),
			},
			want: []string{"configmaps:4", "secrets:3"},
		},
		{
			name: "both config",
			objects: []runtime.Object{
				testRVSecret(userConfigPrefix+"a", "1"),
				testRVConfigMap(userConfigPrefix+"b", "2"),
				testRVSecret(systemConfigPrefix+"c", "3"),
				testRVConfigMap(systemConfigPrefix+"d", "4"),
			},
			want: []string{"configmaps:2", "configmaps:4", "secrets:1", "secrets:3"},
		},
		{
			name: "both config overlapping resource versions",
			objects: []runtime.Object{
				testRVSecret(userConfigPrefix+"a", "1"),
				testRVConfigMap(userConfigPrefix+"b", "2"),
				testRVSecret(systemConfigPrefix+"c", "2"),
				testRVConfigMap(systemConfigPrefix+"d", "1"),
			},
			want: []string{"configmaps:2", "configmaps:1", "secrets:1", "secrets:2"},
		},
		{
			name: "both config overlapping resource versions and ignored data",
			objects: []runtime.Object{
				testRVSecret("e", "5"),
				testRVConfigMap("f", "6"),
				testRVSecret(userConfigPrefix+"a", "3"),
				testRVConfigMap(userConfigPrefix+"b", "2"),
				testRVSecret(systemConfigPrefix+"c", "2"),
				testRVConfigMap(systemConfigPrefix+"d", "3"),
			},
			want: []string{"configmaps:2", "configmaps:3", "secrets:3", "secrets:2"},
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
			Namespace:       targetNamespace,
			ResourceVersion: rv,
		},
	}
}

func testRVConfigMap(name, rv string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       targetNamespace,
			ResourceVersion: rv,
		},
	}
}
