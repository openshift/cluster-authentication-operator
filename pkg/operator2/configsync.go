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

func (c *authOperator) handleConfigSync(config *configv1.OAuth) ([]idpSyncData, error) {
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
	for _, d := range data {
		for dest, src := range d.configMaps {
			syncOrDie(c.resourceSyncer.SyncConfigMap, dest, src.src)
			inUseConfigMapNames.Insert(dest)
		}
		for dest, src := range d.secrets {
			syncOrDie(c.resourceSyncer.SyncSecret, dest, src.src)
			inUseSecretNames.Insert(dest)
		}
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

// TODO: new source data could be generalized
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
func convertToData(idps []configv1.IdentityProvider) []idpSyncData {
	out := make([]idpSyncData, 0, len(idps))
	for i, idp := range idps {
		pc := idp.IdentityProviderConfig
		switch pc.Type {
		case configv1.IdentityProviderTypeBasicAuth:
			p := pc.BasicAuth

			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			clientCert := p.TLSClientCert.Name
			clientCertDest, clientCertData := newSourceDataIDPSecret(i, clientCert, corev1.TLSCertKey)

			clientKey := p.TLSClientKey.Name
			clientKeyDest, clienKeyData := newSourceDataIDPSecret(i, clientKey, corev1.TLSPrivateKeyKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets: map[string]sourceData{
						clientCertDest: clientCertData,
						clientKeyDest:  clienKeyData,
					},
				},
			)

		case configv1.IdentityProviderTypeGitHub:
			p := pc.GitHub
			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			clientSecret := p.ClientSecret.Name
			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, clientSecret, configv1.ClientSecretKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets: map[string]sourceData{
						clientSecretDest: clientSecretData,
					},
				},
			)

		case configv1.IdentityProviderTypeGitLab:
			p := pc.GitLab
			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			clientSecret := p.ClientSecret.Name
			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, clientSecret, configv1.ClientSecretKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets: map[string]sourceData{
						clientSecretDest: clientSecretData,
					},
				},
			)

		case configv1.IdentityProviderTypeGoogle:
			p := pc.Google

			clientSecret := p.ClientSecret.Name
			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, clientSecret, configv1.ClientSecretKey)

			out = append(out,
				idpSyncData{
					secrets: map[string]sourceData{
						clientSecretDest: clientSecretData,
					},
				},
			)

		case configv1.IdentityProviderTypeHTPasswd:
			p := pc.HTPasswd // TODO could panic if invalid (applies to all IDPs)

			fileData := p.FileData.Name
			dest, data := newSourceDataIDPSecret(i, fileData, configv1.HTPasswdDataKey)

			out = append(out,
				idpSyncData{secrets: map[string]sourceData{dest: data}},
			)

		case configv1.IdentityProviderTypeKeystone:
			p := pc.Keystone

			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			clientCert := p.TLSClientCert.Name
			clientCertDest, clientCertData := newSourceDataIDPSecret(i, clientCert, corev1.TLSCertKey)

			clientKey := p.TLSClientKey.Name
			clientKeyDest, clienKeyData := newSourceDataIDPSecret(i, clientKey, corev1.TLSPrivateKeyKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets: map[string]sourceData{
						clientCertDest: clientCertData,
						clientKeyDest:  clienKeyData,
					},
				},
			)

		case configv1.IdentityProviderTypeLDAP:
			p := pc.LDAP

			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			bindPassword := p.BindPassword.Name
			bindPasswordDest, bindPasswordData := newSourceDataIDPSecret(i, bindPassword, configv1.BindPasswordKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets:    map[string]sourceData{bindPasswordDest: bindPasswordData},
				},
			)

		case configv1.IdentityProviderTypeOpenID:
			p := pc.OpenID

			ca := p.CA.Name
			caDest, caData := newSourceDataIDPConfigMap(i, ca, corev1.ServiceAccountRootCAKey)

			clientSecret := p.ClientSecret.Name
			clientSecretDest, clientSecretData := newSourceDataIDPSecret(i, clientSecret, configv1.ClientSecretKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{caDest: caData},
					secrets: map[string]sourceData{
						clientSecretDest: clientSecretData,
					},
				},
			)

		case configv1.IdentityProviderTypeRequestHeader:
			p := pc.RequestHeader

			clientCA := p.ClientCA.Name
			clientCADest, clientCAData := newSourceDataIDPConfigMap(i, clientCA, corev1.ServiceAccountRootCAKey)

			out = append(out,
				idpSyncData{
					configMaps: map[string]sourceData{clientCADest: clientCAData},
				},
			)

		default:
			return nil // TODO: some erroring
		}
	}
	return out
}

const (
	// if one day we ever need to come up with something else, we can still find the old stuff
	versionPrefix = "v4-0-"

	// anything synced from openshift-config into our namespace has this prefix
	userConfigPrefix = versionPrefix + "config-user-"

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
			Namespace: targetName, // TODO fix
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
