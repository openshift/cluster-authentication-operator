package datasync

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

type Volume struct {
	Name       string
	Configmap  bool
	Path       string
	Keys       []string
	MappedKeys map[string]string
	Optional   bool
}

func (v *Volume) Split() (corev1.Volume, corev1.VolumeMount) {
	vol := corev1.Volume{
		Name: v.Name,
	}

	var items []corev1.KeyToPath
	// maps' keys are random,  we need to sort the output to prevent redeployment hotloops
	for _, key := range sets.StringKeySet(v.MappedKeys).List() {
		items = append(items, corev1.KeyToPath{
			Key:  key,
			Path: v.MappedKeys[key],
		})
	}

	for _, key := range v.Keys {
		items = append(items, corev1.KeyToPath{
			Key:  key,
			Path: key,
		})
	}

	if v.Configmap {
		vol.ConfigMap = &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: v.Name,
			},
			Items:    items,
			Optional: &v.Optional,
		}
	} else {
		vol.Secret = &corev1.SecretVolumeSource{
			SecretName: v.Name,
			Items:      items,
			Optional:   &v.Optional,
		}
	}

	return vol, corev1.VolumeMount{
		Name:      v.Name,
		ReadOnly:  true,
		MountPath: v.Path,
	}
}
