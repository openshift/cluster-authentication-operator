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

func (c *authOperator) handleConfigSync(config *configv1.OAuth) (*idpSyncData, error) {
	// TODO handle OAuthTemplates

	// TODO we probably need listers
	configMapClient := c.configMaps.ConfigMaps(targetName)
	secretClient := c.secrets.Secrets(targetName)

	configMaps, err := configMapClient.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	secrets, err := secretClient.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	prefixConfigMapNames := sets.NewString()
	prefixSecretNames := sets.NewString()

	// TODO this has too much boilerplate

	for _, cm := range configMaps.Items {
		if strings.HasPrefix(cm.Name, userConfigPrefixIDP) {
			prefixConfigMapNames.Insert(cm.Name)
		}
	}

	for _, secret := range secrets.Items {
		if strings.HasPrefix(secret.Name, userConfigPrefixIDP) {
			prefixSecretNames.Insert(secret.Name)
		}
	}

	inUseConfigMapNames := sets.NewString()
	inUseSecretNames := sets.NewString()

	data := convertToData(config.Spec.IdentityProviders)

	for dest, src := range data.configMaps {
		syncOrDie(c.resourceSyncer.SyncConfigMap, dest, src.src)
		inUseConfigMapNames.Insert(dest)
	}
	for dest, src := range data.secrets {
		syncOrDie(c.resourceSyncer.SyncSecret, dest, src.src)
		inUseSecretNames.Insert(dest)
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

	return data, nil
}

type idpSyncData struct {
	// both maps are dest -> source
	// dest is metadata.name for resource in our deployment's namespace
	configMaps map[string]sourceData
	secrets    map[string]sourceData
}

type sourceData struct {
	src    string
	path   string
	volume corev1.Volume
	mount  corev1.VolumeMount
}

// TODO: newSourceDataIDP* could be a generic function grouping the common pieces of code
// newSourceDataIDPSecret returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mountvolumes to mount the secret to
func newSourceDataIDPSecret(index int, secretName, idpType string) (string, sourceData) {
	dest := getIDPName(index, secretName, idpType)

	volume, mount, path := secretVolume(index, dest, idpType)
	ret := sourceData{
		src:    secretName,
		path:   path,
		volume: volume,
		mount:  mount,
	}

	return dest, ret
}

// newSourceDataIDPConfigMap returns a name which is unique amongst the IdPs, and
// sourceData which describes the volumes and mountvolumes to mount the ConfigMap to
func newSourceDataIDPConfigMap(index int, cmName, idpType string) (string, sourceData) {
	dest := getIDPName(index, cmName, idpType)

	volume, mount, path := configMapVolume(index, dest, idpType)
	ret := sourceData{
		src:    cmName,
		path:   path,
		volume: volume,
		mount:  mount,
	}

	return dest, ret
}

// TODO this should be combined with convertProviderConfigToOsinBytes as it would simplify how the data is shared
func convertToData(idps []configv1.IdentityProvider) *idpSyncData {
	configMaps := map[string]sourceData{}
	secrets := map[string]sourceData{}

	for i, idp := range idps {
		pc := idp.IdentityProviderConfig
		switch pc.Type {
		case configv1.IdentityProviderTypeBasicAuth:
			p := pc.BasicAuth

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			clientCertDest, clientCertData := newSourceDataIDPSecret(i, p.TLSClientCert.Name, corev1.TLSCertKey)
			secrets[clientCertDest] = clientCertData

			clientKeyDest, clientKeyData := newSourceDataIDPSecret(i, p.TLSClientKey.Name, corev1.TLSPrivateKeyKey)
			secrets[clientKeyDest] = clientKeyData

		case configv1.IdentityProviderTypeGitHub:
			p := pc.GitHub

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, p.ClientSecret.Name, configv1.ClientSecretKey)
			secrets[clientSecretDest] = clientSecretData

		case configv1.IdentityProviderTypeGitLab:
			p := pc.GitLab

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, p.ClientSecret.Name, configv1.ClientSecretKey)
			secrets[clientSecretDest] = clientSecretData

		case configv1.IdentityProviderTypeGoogle:
			p := pc.Google

			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, p.ClientSecret.Name, configv1.ClientSecretKey)
			secrets[clientSecretDest] = clientSecretData

		case configv1.IdentityProviderTypeHTPasswd:
			p := pc.HTPasswd // TODO could panic if invalid (applies to all IDPs)

			dest, data := newSourceDataIDPSecret(i, p.FileData.Name, configv1.HTPasswdDataKey)
			secrets[dest] = data

		case configv1.IdentityProviderTypeKeystone:
			p := pc.Keystone

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			clientCertDest, clientCertData := newSourceDataIDPSecret(i, p.TLSClientCert.Name, corev1.TLSCertKey)
			secrets[clientCertDest] = clientCertData

			clientKeyDest, clientKeyData := newSourceDataIDPSecret(i, p.TLSClientKey.Name, corev1.TLSPrivateKeyKey)
			secrets[clientKeyDest] = clientKeyData

		case configv1.IdentityProviderTypeLDAP:
			p := pc.LDAP

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			bindPasswordDest, bindPasswordData := newSourceDataIDPSecret(i, p.BindPassword.Name, configv1.BindPasswordKey)
			secrets[bindPasswordDest] = bindPasswordData

		case configv1.IdentityProviderTypeOpenID:
			p := pc.OpenID

			caDest, caData := newSourceDataIDPConfigMap(i, p.CA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[caDest] = caData

			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, p.ClientSecret.Name, configv1.ClientSecretKey)
			secrets[clientSecretDest] = clientSecretData

		case configv1.IdentityProviderTypeRequestHeader:
			p := pc.RequestHeader

			clientCADest, clientCAData := newSourceDataIDPConfigMap(i, p.ClientCA.Name, corev1.ServiceAccountRootCAKey)
			configMaps[clientCADest] = clientCAData

		default:
			return nil // TODO: some erroring
		}
	}
	return &idpSyncData{
		configMaps: configMaps,
		secrets:    secrets,
	}
}

const (
	// idps that are synced have this prefix
	userConfigPrefixIDP = userConfigPrefix + "idp-"

	// templates that are synced have this prefix
	// TODO actually handle templates
	userConfigPrefixTemplate = userConfigPrefix + "template-"

	// root path for IDP data
	userConfigPathPrefixIDP = userConfigPath + "/idp/"

	// root path for template data
	userConfigPathPrefixTemplate = userConfigPath + "/template/"
)

func getIDPName(i int, name, key string) string {
	// TODO this scheme relies on each IDP struct not using the same key for more than one field
	// I think we can do better, but here is a start
	// A generic function that uses reflection may work too
	// granted the key bit can be easily solved by the caller adding a postfix to the key if it is reused
	newKey := strings.Replace(strings.ToLower(key), ".", "-", -1)
	return fmt.Sprintf("%s%d-%s-%s", userConfigPrefixIDP, i, name, newKey)
}

func getIDPPath(i int, resource, name string) string {
	return fmt.Sprintf("%s%d/%s/%s", userConfigPathPrefixIDP, i, resource, name)
}

func syncOrDie(syncFunc func(dest, src resourcesynccontroller.ResourceLocation) error, dest, src string) {
	ns := userConfigNamespace
	if len(src) == 0 { // handle delete
		ns = ""
	}
	if err := syncFunc(
		resourcesynccontroller.ResourceLocation{
			Namespace: targetName,
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

func secretVolume(i int, name, key string) (corev1.Volume, corev1.VolumeMount, string) {
	volume := corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: name,
				Items: []corev1.KeyToPath{
					{
						Key:  key,
						Path: key,
					},
				},
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      name,
		ReadOnly:  true,
		MountPath: getIDPPath(i, "secret", name),
	}
	return volume, mount, mount.MountPath + "/" + key
}

func configMapVolume(i int, name, key string) (corev1.Volume, corev1.VolumeMount, string) {
	volume := corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: name,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  key,
						Path: key,
					},
				},
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      name,
		ReadOnly:  true,
		MountPath: getIDPPath(i, "configmap", name),
	}
	return volume, mount, mount.MountPath + "/" + key
}
