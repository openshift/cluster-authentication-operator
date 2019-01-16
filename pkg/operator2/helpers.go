package operator2

import configv1 "github.com/openshift/api/config/v1"

func moveSecretFromRefToFileStringSource(syncData *idpSyncData, i int, name configv1.SecretNameReference, key string) configv1.StringSource {
	return configv1.StringSource{
		StringSourceSpec: configv1.StringSourceSpec{
			File: getFilenameFromSecretNameRef(syncData, i, name, key),
		},
	}
}

func getFilenameFromConfigMapNameRef(syncData *idpSyncData, i int, name configv1.ConfigMapNameReference, key string) string {
	// TODO make sure this makes sense (some things are optional)
	return syncData.configMaps[getIDPName(i, name.Name, key)].path
}

func getFilenameFromSecretNameRef(syncData *idpSyncData, i int, name configv1.SecretNameReference, key string) string {
	// TODO make sure this makes sense (some things are optional)
	return syncData.secrets[getIDPName(i, name.Name, key)].path
}
