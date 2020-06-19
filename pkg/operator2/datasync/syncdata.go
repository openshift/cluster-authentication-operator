package datasync

import (
	"encoding/json"
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corelistersv1 "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type ConfigSyncData struct {
	// data maps dest -> source
	// dest is metadata.name for resource in our deployment's namespace
	data map[string]sourceData
}

type ResourceType string

const (
	ConfigMapType ResourceType = "configMap"
	SecretType    ResourceType = "secret"
)

type sourceData struct {
	Name      string       `json:"name"`      // name of the source in openshift-config namespace
	MountPath string       `json:"mountPath"` // the mount path that this source is mapped to
	Key       string       `json:"key"`
	Type      ResourceType `json:"type"`
}

func HandleIdPConfigSync(resourceSyncer resourcesynccontroller.ResourceSyncer, oldData, newData *ConfigSyncData) {
	newConfigMapNames := sets.NewString()
	newSecretNames := sets.NewString()

	oldConfigMapNames := sets.NewString()
	oldSecretNames := sets.NewString()

	for _, dest := range sets.StringKeySet(newData.data).List() {
		syncFunc := resourceSyncer.SyncSecret

		if newData.data[dest].Type == ConfigMapType {
			syncFunc = resourceSyncer.SyncConfigMap
			newConfigMapNames.Insert(dest)
		} else {
			newSecretNames.Insert(dest)
		}

		SyncConfigOrDie(syncFunc, dest, newData.data[dest].Name)
	}

	for _, dest := range sets.StringKeySet(oldData.data).List() {
		if oldData.data[dest].Type == ConfigMapType {
			oldConfigMapNames.Insert(dest)
		} else {
			oldSecretNames.Insert(dest)
		}
	}

	unusedConfigMapNames := oldConfigMapNames.Difference(newConfigMapNames)
	unusedSecretNames := oldSecretNames.Difference(newSecretNames)

	// TODO maybe update resource syncer in lib-go to cleanup its map as needed
	// it does not really matter, we are talking as worse case of
	// a few unneeded strings and a few unnecessary deletes
	for dest := range unusedConfigMapNames {
		SyncConfigOrDie(resourceSyncer.SyncConfigMap, dest, "")
	}
	for dest := range unusedSecretNames {
		SyncConfigOrDie(resourceSyncer.SyncSecret, dest, "")
	}
}

// newSourceDataIDP returns a name which is unique amongst the IdPs, and sourceData
// which describes the volumes and mount volumes to mount the CM/Secret to
func newSourceDataIDP(index int, resourceType ResourceType, resourceName, field, key string) (string, sourceData) {
	dest := getIDPName(index, field)
	dirPath := getIDPPath(index, string(resourceType), dest)

	return dest, sourceData{
		Name:      resourceName,
		MountPath: dirPath,
		Key:       key,
		Type:      resourceType,
	}
}

func NewConfigSyncData() *ConfigSyncData {
	return &ConfigSyncData{
		data: map[string]sourceData{},
	}
}

func NewConfigSyncDataFromJSON(jsBytes []byte) (*ConfigSyncData, error) {
	data := map[string]sourceData{}
	if len(jsBytes) > 0 {
		if err := json.Unmarshal(jsBytes, &data); err != nil {
			return nil, fmt.Errorf("%s: %v", jsBytes, err)
		}
	}
	return &ConfigSyncData{data: data}, nil
}

// Bytes returns JSON representation of the structure's internal data map
func (sd *ConfigSyncData) Bytes() ([]byte, error) {
	return json.Marshal(sd.data)
}

// Validate checks that the data to be synchronized is all present, has the required
// fields, and performs additional validation of certificates and keys
func (sd *ConfigSyncData) Validate(cmLister corelistersv1.ConfigMapLister, secretsLister corelistersv1.SecretLister) []error {
	errs := []error{}
	for _, src := range sd.data {
		if src.Type == SecretType {
			if secretErrs := validateSecret(secretsLister, src); len(secretErrs) > 0 {
				errs = append(errs, fmt.Errorf("error validating secret openshift-config/%s: %w", src.Name, errors.NewAggregate(secretErrs)))
			}
		} else if cmErrs := validateConfigMap(cmLister, src); len(cmErrs) > 0 {
			errs = append(errs, fmt.Errorf("error validating configMap openshift-config/%s: %w", src.Name, errors.NewAggregate(cmErrs)))
		}
	}
	return errs
}

// AddIDPSecret initializes a sourceData object with proper data for a Secret
// and adds it among the other secrets stored here
// Returns the path for the Secret
func (sd *ConfigSyncData) AddIDPSecret(index int, secretRef configv1.SecretNameReference, field, key string) string {
	if len(secretRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDP(index, SecretType, secretRef.Name, field, key)
	sd.data[dest] = data

	return path.Join(data.MountPath, key)
}

// AddIDPConfigMap initializes a sourceData object with proper data for a ConfigMap
// and adds it among the other configmaps stored here
// Returns the path for the ConfigMap
func (sd *ConfigSyncData) AddIDPConfigMap(index int, configMapRef configv1.ConfigMapNameReference, field, key string) string {
	if len(configMapRef.Name) == 0 {
		return ""
	}

	dest, data := newSourceDataIDP(index, ConfigMapType, configMapRef.Name, field, key)
	sd.data[dest] = data

	return path.Join(data.MountPath, key)
}

// ToVolumesAndMounts converts the synchronization data to Volumes and VoulumeMounts
// so that these can be added to a container spec
func (sd *ConfigSyncData) ToVolumesAndMounts() ([]corev1.Volume, []corev1.VolumeMount, error) {
	volumes := []corev1.Volume{}
	volumeMounts := []corev1.VolumeMount{}

	// maps' keys are random,  we need to sort the output to prevent redeployment hotloops
	for _, dataKey := range sets.StringKeySet(sd.data).List() {
		volume, volumeMount, err := sd.data[dataKey].ToVolumesAndMounts(dataKey)
		if err != nil {
			return nil, nil, err
		}

		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	return volumes, volumeMounts, nil

}

func (s sourceData) ToVolumesAndMounts(volName string) (*corev1.Volume, *corev1.VolumeMount, error) {
	vol := &corev1.Volume{
		Name: volName,
	}

	items := []corev1.KeyToPath{
		{
			Key:  s.Key,
			Path: s.Key,
		},
	}

	switch s.Type {
	case ConfigMapType:
		vol.ConfigMap = &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: volName,
			},
			Items: items,
		}
	case SecretType:
		vol.Secret = &corev1.SecretVolumeSource{
			SecretName: volName,
			Items:      items,
		}
	default:
		return nil, nil, fmt.Errorf("unknown resource type: %s", s.Type)
	}

	return vol, &corev1.VolumeMount{
		Name:      volName,
		ReadOnly:  true,
		MountPath: s.MountPath,
	}, nil
}

func getIDPName(i int, field string) string {
	// idps that are synced have this prefix
	return fmt.Sprintf("v4-0-config-user-idp-%d-%s", i, field)
}

func getIDPPath(i int, resource, dest string) string {
	// root path for IDP data
	return fmt.Sprintf("/var/config/user/idp/%d/%s/%s", i, resource, dest)
}

func SyncConfigOrDie(syncFunc func(dest, src resourcesynccontroller.ResourceLocation) error, dest, src string) {
	ns := "openshift-config"
	if len(src) == 0 {
		// handle deletion of the source by prompting the syncer to delete the image
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
