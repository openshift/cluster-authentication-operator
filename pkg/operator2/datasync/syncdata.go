package datasync

import (
	"fmt"
	"path"

	"k8s.io/apimachinery/pkg/util/sets"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type ConfigSyncData struct {
	// both maps are dest -> source
	// dest is metadata.name for resource in our deployment's namespace
	IdPConfigMaps map[string]sourceData
	IdPSecrets    map[string]sourceData
}

type ResourceType string

const (
	ConfigMapType ResourceType = "ConfigMap"
	SecretType    ResourceType = "Secret"
)

type sourceData struct {
	Src      string `json:"src"` // name of the source in openshift-config namespace
	Path     string // the mount path that this source is mapped to
	Key      string
	Resource ResourceType
}

func HandleIdPConfigSync(resourceSyncer resourcesynccontroller.ResourceSyncer, oldData, newData *ConfigSyncData) {
	// TODO this has too much boilerplate

	newConfigMapNames := sets.NewString()
	newSecretNames := sets.NewString()

	oldConfigMapNames := sets.NewString()
	oldSecretNames := sets.NewString()

	for _, dest := range sets.StringKeySet(newData.IdPConfigMaps).List() {
		syncOrDie(resourceSyncer.SyncConfigMap, dest, newData.IdPConfigMaps[dest].Src)
		newConfigMapNames.Insert(dest)
	}
	for _, dest := range sets.StringKeySet(newData.IdPSecrets).List() {
		syncOrDie(resourceSyncer.SyncSecret, dest, newData.IdPSecrets[dest].Src)
		newSecretNames.Insert(dest)
	}

	for _, dst := range sets.StringKeySet(oldData.IdPConfigMaps).List() {
		oldConfigMapNames.Insert(dst)
	}

	for _, dst := range sets.StringKeySet(oldData.IdPSecrets).List() {
		oldSecretNames.Insert(dst)
	}

	// TODO: (?) originally we were testing that all CMs and Secrets are synced by listing CMs and Secrets in the target NS

	notInUseConfigMapNames := oldConfigMapNames.Difference(newConfigMapNames)
	notInUseSecretNames := oldSecretNames.Difference(newSecretNames)

	// TODO maybe update resource syncer in lib-go to cleanup its map as needed
	// it does not really matter, we are talking as worse case of
	// a few unneeded strings and a few unnecessary deletes
	for dest := range notInUseConfigMapNames {
		syncOrDie(resourceSyncer.SyncConfigMap, dest, "")
	}
	for dest := range notInUseSecretNames {
		syncOrDie(resourceSyncer.SyncSecret, dest, "")
	}
}

// TODO: newSourceDataIDP* could be a generic function grouping the common pieces of code
// newSourceDataIDPSecret returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mount volumes to mount the secret to
func newSourceDataIDPSecret(index int, secretName configv1.SecretNameReference, field, key string) (string, sourceData) {
	dest := getIDPName(index, field)
	dirPath := getIDPPath(index, "secret", dest)

	// vol, mount, path := secretVolume(dirPath, dest, key)
	ret := sourceData{
		Src:      secretName.Name,
		Path:     dirPath,
		Key:      key,
		Resource: SecretType,
	}

	return dest, ret
}

// newSourceDataIDPConfigMap returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mountvolumes to mount the ConfigMap to
func newSourceDataIDPConfigMap(index int, configMap configv1.ConfigMapNameReference, field, key string) (string, sourceData) {
	dest := getIDPName(index, field)
	dirPath := getIDPPath(index, "configmap", dest)

	ret := sourceData{
		Src:      configMap.Name,
		Path:     dirPath,
		Key:      key,
		Resource: ConfigMapType,
	}

	return dest, ret
}

func NewConfigSyncData() ConfigSyncData {
	return ConfigSyncData{
		IdPConfigMaps: map[string]sourceData{},
		IdPSecrets:    map[string]sourceData{},
	}
}

// AddSecret initializes a sourceData object with proper data for a Secret
// and adds it among the other secrets stored here
// Returns the path for the Secret
func (sd *ConfigSyncData) AddIDPSecret(index int, secretRef configv1.SecretNameReference, field, key string) string {
	if len(secretRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDPSecret(index, secretRef, field, key)
	sd.IdPSecrets[dest] = data

	return path.Join(data.Path, key)
}

// AddConfigMap initializes a sourceData object with proper data for a ConfigMap
// and adds it among the other configmaps stored here
// Returns the path for the ConfigMap
func (sd *ConfigSyncData) AddIDPConfigMap(index int, configMapRef configv1.ConfigMapNameReference, field, key string) string {
	if len(configMapRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDPConfigMap(index, configMapRef, field, key)
	sd.IdPConfigMaps[dest] = data

	return path.Join(data.Path, key)
}

func (sd *ConfigSyncData) ToVolumes() []Volume {
	ret := []Volume{}

	// FIXME: this is quite obviously unnecessary, maybe just have one string map for everything
	for k, v := range sd.IdPConfigMaps {
		ret = append(ret,
			Volume{
				Name:      k,
				Configmap: true,
				Path:      v.Path,
				Keys:      []string{v.Key},
			})
	}

	for k, v := range sd.IdPSecrets {
		ret = append(ret,
			Volume{
				Name:      k,
				Configmap: false,
				Path:      v.Path,
				Keys:      []string{v.Key},
			})
	}

	return ret
}

func getIDPName(i int, field string) string {
	// idps that are synced have this prefix
	return fmt.Sprintf("%s%d-%s", "v4-0-config-user-idp-", i, field)
}

func getIDPPath(i int, resource, dest string) string {
	// root path for IDP data
	return fmt.Sprintf("%s/%d/%s/%s", "/var/config/user/idp", i, resource, dest)
}

func syncOrDie(syncFunc func(dest, src resourcesynccontroller.ResourceLocation) error, dest, src string) {
	ns := "openshift-config"
	if len(src) == 0 { // handle delete
		ns = ""
	}
	if err := syncFunc(
		resourcesynccontroller.ResourceLocation{
			Namespace: "openshift-authentication",
			Name:      dest,
		},
		resourcesynccontroller.ResourceLocation{
			Namespace: ns,
			Name:      src,
		},
	); err != nil {
		panic(err) // implies incorrect informer wiring, we can never recover from this, just die
	}
}
