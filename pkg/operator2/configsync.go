package operator2

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

func (c *authOperator) handleConfigSync(data *configSyncData) error {
	// TODO this has too much boilerplate

	inUseConfigMapNames := sets.NewString()
	inUseSecretNames := sets.NewString()

	for _, dest := range sets.StringKeySet(data.idpConfigMaps).List() {
		syncOrDie(c.resourceSyncer.SyncConfigMap, dest, data.idpConfigMaps[dest].src)
		inUseConfigMapNames.Insert(dest)
	}
	for _, dest := range sets.StringKeySet(data.idpSecrets).List() {
		syncOrDie(c.resourceSyncer.SyncSecret, dest, data.idpSecrets[dest].src)
		inUseSecretNames.Insert(dest)
	}
	for _, dest := range sets.StringKeySet(data.tplSecrets).List() {
		syncOrDie(c.resourceSyncer.SyncSecret, dest, data.tplSecrets[dest].src)
		inUseSecretNames.Insert(dest)
	}

	// TODO we probably need listers

	configMaps, err := c.configMaps.ConfigMaps(targetNamespace).List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	configMapNames := sets.NewString()
	prefixConfigMapNames := sets.NewString()
	for _, cm := range configMaps.Items {
		configMapNames.Insert(cm.Name)
		if strings.HasPrefix(cm.Name, userConfigPrefix) {
			prefixConfigMapNames.Insert(cm.Name)
		}
	}
	if !configMapNames.IsSuperset(inUseConfigMapNames) {
		return fmt.Errorf("config maps %s in %s not synced", inUseConfigMapNames.Difference(configMapNames).List(), targetNamespace)
	}

	secrets, err := c.secrets.Secrets(targetNamespace).List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	secretNames := sets.NewString()
	prefixSecretNames := sets.NewString()
	for _, secret := range secrets.Items {
		secretNames.Insert(secret.Name)
		if strings.HasPrefix(secret.Name, userConfigPrefix) {
			prefixSecretNames.Insert(secret.Name)
		}
	}
	if !secretNames.IsSuperset(inUseSecretNames) {
		return fmt.Errorf("secrets %s in %s not synced", inUseSecretNames.Difference(secretNames).List(), targetNamespace)
	}

	notInUseConfigMapNames := prefixConfigMapNames.Difference(inUseConfigMapNames)
	notInUseSecretNames := prefixSecretNames.Difference(inUseSecretNames)

	// TODO maybe update resource syncer in lib-go to cleanup its map as needed
	// it does not really matter, we are talking as worse case of
	// a few unneeded strings and a few unnecessary deletes
	for dest := range notInUseConfigMapNames {
		syncOrDie(c.resourceSyncer.SyncConfigMap, dest, "")
	}
	for dest := range notInUseSecretNames {
		syncOrDie(c.resourceSyncer.SyncSecret, dest, "")
	}

	return nil
}

type configSyncData struct {
	// both maps are dest -> source
	// dest is metadata.name for resource in our deployment's namespace
	idpConfigMaps map[string]sourceData
	idpSecrets    map[string]sourceData
	tplSecrets    map[string]sourceData
}

type sourceData struct {
	src    string // name of the source in openshift-config namespace
	path   string // the mount path that this source is mapped to
	volume corev1.Volume
	mount  corev1.VolumeMount
}

// TODO: newSourceDataIDP* could be a generic function grouping the common pieces of code
// newSourceDataIDPSecret returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mount volumes to mount the secret to
func newSourceDataIDPSecret(index int, secretName configv1.SecretNameReference, field, key string) (string, sourceData) {
	dest := getIDPName(index, field)
	dirPath := getIDPPath(index, "secret", dest)

	vol, mount, path := secretVolume(dirPath, dest, key)
	ret := sourceData{
		src:    secretName.Name,
		path:   path,
		volume: vol,
		mount:  mount,
	}

	return dest, ret
}

// newSourceDataIDPConfigMap returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mountvolumes to mount the ConfigMap to
func newSourceDataIDPConfigMap(index int, configMap configv1.ConfigMapNameReference, field, key string) (string, sourceData) {
	dest := getIDPName(index, field)
	dirPath := getIDPPath(index, "configmap", dest)

	vol, mount, path := configMapVolume(dirPath, dest, key)
	ret := sourceData{
		src:    configMap.Name,
		path:   path,
		volume: vol,
		mount:  mount,
	}

	return dest, ret
}

func newSourceDataTemplateSecret(secretRef configv1.SecretNameReference, field, key string) (string, sourceData) {
	dest := getTemplateName(field)
	dirPath := getTemplatePath("secret", dest)

	vol, mount, path := secretVolume(dirPath, dest, key)
	ret := sourceData{
		src:    secretRef.Name,
		path:   path,
		volume: vol,
		mount:  mount,
	}

	return dest, ret
}

func newConfigSyncData() configSyncData {
	idpConfigMaps := map[string]sourceData{}
	idpSecrets := map[string]sourceData{}
	tplSecrets := map[string]sourceData{}

	return configSyncData{
		idpConfigMaps: idpConfigMaps,
		idpSecrets:    idpSecrets,
		tplSecrets:    tplSecrets,
	}
}

// AddSecret initializes a sourceData object with proper data for a Secret
// and adds it among the other secrets stored here
// Returns the path for the Secret
func (sd *configSyncData) addIDPSecret(index int, secretRef configv1.SecretNameReference, field, key string) string {
	if len(secretRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDPSecret(index, secretRef, field, key)
	sd.idpSecrets[dest] = data

	return data.path
}

// AddConfigMap initializes a sourceData object with proper data for a ConfigMap
// and adds it among the other configmaps stored here
// Returns the path for the ConfigMap
func (sd *configSyncData) addIDPConfigMap(index int, configMapRef configv1.ConfigMapNameReference, field, key string) string {
	if len(configMapRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDPConfigMap(index, configMapRef, field, key)
	sd.idpConfigMaps[dest] = data

	return data.path
}

func (sd *configSyncData) addTemplateSecret(secretRef configv1.SecretNameReference, field, key string) string {
	if len(secretRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataTemplateSecret(secretRef, field, key)
	sd.tplSecrets[dest] = data

	return data.path
}

func getIDPName(i int, field string) string {
	return fmt.Sprintf("%s%d-%s", userConfigPrefixIDP, i, field)
}

func getIDPPath(i int, resource, dest string) string {
	return fmt.Sprintf("%s/%d/%s/%s", userConfigPathPrefixIDP, i, resource, dest)
}

func getTemplateName(field string) string {
	return userConfigPrefixTemplate + field
}

func getTemplatePath(resource, dest string) string {
	return fmt.Sprintf("%s/%s/%s", userConfigPathPrefixTemplate, resource, dest)
}

func syncOrDie(syncFunc func(dest, src resourcesynccontroller.ResourceLocation) error, dest, src string) {
	ns := userConfigNamespace
	if len(src) == 0 { // handle delete
		ns = ""
	}
	if err := syncFunc(
		resourcesynccontroller.ResourceLocation{
			Namespace: targetNamespace,
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

func secretVolume(path, name, key string) (corev1.Volume, corev1.VolumeMount, string) {
	data := volume{
		name:      name,
		configmap: false,
		path:      path,
		keys:      []string{key},
	}

	vol, mount := data.split()

	return vol, mount, mount.MountPath + "/" + key
}

func configMapVolume(path, name, key string) (corev1.Volume, corev1.VolumeMount, string) {
	data := volume{
		name:      name,
		configmap: true,
		path:      path,
		keys:      []string{key},
	}

	vol, mount := data.split()

	return vol, mount, mount.MountPath + "/" + key
}
