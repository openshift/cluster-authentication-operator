package operator2

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

func Test_authOperator_handleConfigSync(t *testing.T) {
	tests := []struct {
		name           string
		objects        []runtime.Object
		idpConfigMaps  map[string]string
		idpSecrets     map[string]string
		tplSecrets     map[string]string
		wantConfigMaps []location
		wantSecrets    []location
		wantErr        string
	}{
		{
			name: "nothing synced yet",
			objects: []runtime.Object{
				testConfigSyncSecret("a"),
				testConfigSyncConfigMap("b"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-a": "src-a",
				"v4-0-config-user-dest-b": "src-b",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-c": "src-c",
				"v4-0-config-user-dest-d": "src-d",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-e": "src-e",
				"v4-0-config-user-dest-f": "src-f",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-a"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-a"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-b"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-b"},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-c"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-c"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-d"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-d"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-e"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-e"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-f"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-f"},
				},
			},
			wantErr: "config maps [v4-0-config-user-dest-a v4-0-config-user-dest-b] in openshift-authentication not synced",
		},
		{
			name: "some config maps synced",
			objects: []runtime.Object{
				testConfigSyncSecret("a"),
				testConfigSyncConfigMap("b"),

				testConfigSyncConfigMap("v4-0-config-user-dest-a"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-a": "src-a",
				"v4-0-config-user-dest-b": "src-b",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-c": "src-c",
				"v4-0-config-user-dest-d": "src-d",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-e": "src-e",
				"v4-0-config-user-dest-f": "src-f",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-a"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-a"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-b"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-b"},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-c"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-c"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-d"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-d"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-e"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-e"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-f"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-f"},
				},
			},
			wantErr: "config maps [v4-0-config-user-dest-b] in openshift-authentication not synced",
		},
		{
			name: "all config maps synced",
			objects: []runtime.Object{
				testConfigSyncSecret("a"),
				testConfigSyncConfigMap("b"),

				testConfigSyncConfigMap("v4-0-config-user-dest-a"),
				testConfigSyncConfigMap("v4-0-config-user-dest-b"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-a": "src-a",
				"v4-0-config-user-dest-b": "src-b",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-c": "src-c",
				"v4-0-config-user-dest-d": "src-d",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-e": "src-e",
				"v4-0-config-user-dest-f": "src-f",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-a"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-a"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-b"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-b"},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-c"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-c"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-d"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-d"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-e"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-e"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-f"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-f"},
				},
			},
			wantErr: "secrets [v4-0-config-user-dest-c v4-0-config-user-dest-d v4-0-config-user-dest-e v4-0-config-user-dest-f] in openshift-authentication not synced",
		},
		{
			name: "all config maps and secrets synced",
			objects: []runtime.Object{
				testConfigSyncSecret("a"),
				testConfigSyncConfigMap("b"),

				testConfigSyncConfigMap("v4-0-config-user-dest-a"),
				testConfigSyncConfigMap("v4-0-config-user-dest-b"),

				testConfigSyncSecret("v4-0-config-user-dest-c"),
				testConfigSyncSecret("v4-0-config-user-dest-d"),
				testConfigSyncSecret("v4-0-config-user-dest-e"),
				testConfigSyncSecret("v4-0-config-user-dest-f"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-a": "src-a",
				"v4-0-config-user-dest-b": "src-b",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-c": "src-c",
				"v4-0-config-user-dest-d": "src-d",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-e": "src-e",
				"v4-0-config-user-dest-f": "src-f",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-a"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-a"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-b"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-b"},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-c"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-c"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-d"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-d"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-e"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-e"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-f"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-f"},
				},
			},
			wantErr: "",
		},
		{
			name: "all config maps and secrets synced with old data",
			objects: []runtime.Object{
				testConfigSyncSecret("a"),
				testConfigSyncConfigMap("b"),

				testConfigSyncConfigMap("v4-0-config-user-dest-a"),
				testConfigSyncConfigMap("v4-0-config-user-dest-b"),

				testConfigSyncSecret("v4-0-config-user-dest-c"),
				testConfigSyncSecret("v4-0-config-user-dest-d"),
				testConfigSyncSecret("v4-0-config-user-dest-e"),
				testConfigSyncSecret("v4-0-config-user-dest-f"),

				testConfigSyncSecret("v4-0-config-user-dest-g"),
				testConfigSyncConfigMap("v4-0-config-user-dest-h"),

				testConfigSyncConfigMap(("v4-0-config-system-") + "dest-i"),
				testConfigSyncConfigMap(("v4-0-config-system-") + "dest-j"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-a": "src-a",
				"v4-0-config-user-dest-b": "src-b",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-c": "src-c",
				"v4-0-config-user-dest-d": "src-d",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-e": "src-e",
				"v4-0-config-user-dest-f": "src-f",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-a"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-a"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-b"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-b"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-h"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "", Name: ""},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-c"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-c"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-d"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-d"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-e"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-e"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-f"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-f"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-g"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "", Name: ""},
				},
			},
			wantErr: "",
		},
		{
			name: "all config maps and secrets synced with old data and duplicate sources",
			objects: []runtime.Object{
				testConfigSyncSecret("panda"),
				testConfigSyncConfigMap("bear"),

				testConfigSyncConfigMap("v4-0-config-user-dest-0"),
				testConfigSyncConfigMap("v4-0-config-user-dest-1"),

				testConfigSyncSecret("v4-0-config-user-dest-2"),
				testConfigSyncSecret("v4-0-config-user-dest-3"),
				testConfigSyncSecret("v4-0-config-user-dest-4"),
				testConfigSyncSecret("v4-0-config-user-dest-5"),

				testConfigSyncSecret("v4-0-config-user-dest-6"),
				testConfigSyncConfigMap("v4-0-config-user-dest-7"),

				testConfigSyncConfigMap(("v4-0-config-system-") + "dest-8"),
				testConfigSyncSecret(("v4-0-config-system-") + "dest-9"),
			},
			idpConfigMaps: map[string]string{
				"v4-0-config-user-dest-0": "src-0",
				"v4-0-config-user-dest-1": "src-0",
			},
			idpSecrets: map[string]string{
				"v4-0-config-user-dest-2": "src-1",
				"v4-0-config-user-dest-3": "src-1",
			},
			tplSecrets: map[string]string{
				"v4-0-config-user-dest-4": "src-1",
				"v4-0-config-user-dest-5": "src-1",
			},
			wantConfigMaps: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-0"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-0"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-1"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-0"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-7"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "", Name: ""},
				},
			},
			wantSecrets: []location{
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-2"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-1"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-3"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-1"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-4"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-1"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-5"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: "src-1"},
				},
				{
					destination: resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: "v4-0-config-user-dest-6"},
					source:      resourcesynccontroller.ResourceLocation{Namespace: "", Name: ""},
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			r := &recordingResourceSyncer{}
			c := &authOperator{
				secrets:        client.CoreV1(),
				configMaps:     client.CoreV1(),
				resourceSyncer: r,
			}
			data := &configSyncData{
				idpConfigMaps: testSourceData(tt.idpConfigMaps),
				idpSecrets:    testSourceData(tt.idpSecrets),
				tplSecrets:    testSourceData(tt.tplSecrets),
			}
			if err := c.handleConfigSync(data); errString(err) != tt.wantErr {
				t.Errorf("handleConfigSync() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(r.configMaps, tt.wantConfigMaps) {
				t.Errorf("handleConfigSync() config maps got = %v, want %v", r.configMaps, tt.wantConfigMaps)
			}
			if !reflect.DeepEqual(r.secrets, tt.wantSecrets) {
				t.Errorf("handleConfigSync() secrets got = %v, want %v", r.secrets, tt.wantSecrets)
			}
		})
	}
}

type location struct {
	destination, source resourcesynccontroller.ResourceLocation
}

type recordingResourceSyncer struct {
	configMaps []location
	secrets    []location
}

func (r *recordingResourceSyncer) SyncConfigMap(destination, source resourcesynccontroller.ResourceLocation) error {
	r.configMaps = append(r.configMaps, location{destination: destination, source: source})
	return nil
}

func (r *recordingResourceSyncer) SyncSecret(destination, source resourcesynccontroller.ResourceLocation) error {
	r.secrets = append(r.secrets, location{destination: destination, source: source})
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	if len(errStr) == 0 {
		panic("invalid error")
	}
	return errStr
}

func testSourceData(destToSrc map[string]string) map[string]sourceData {
	out := map[string]sourceData{}
	for dest, src := range destToSrc {
		out[dest] = sourceData{src: src}
	}
	return out
}

func testConfigSyncSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-authentication",
		},
	}
}

func testConfigSyncConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-authentication",
		},
	}
}
