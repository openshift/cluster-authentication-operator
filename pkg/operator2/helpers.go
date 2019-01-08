package operator2

import configv1 "github.com/openshift/api/config/v1"

func moveSecretFromRefToFileStringSource(ref configv1.SecretNameReference) configv1.StringSource {
	return configv1.StringSource{
		StringSourceSpec: configv1.StringSourceSpec{
			File: getFilenameFromSecretNameRef(ref),
		},
	}
}

// TODO: the logic of naming the CMs and Secrets to be mounted to the OSIN container
// TODO: we need to keep track of everything that needs to be mounted in the containers?
func getFilenameFromConfigMapNameRef(ref configv1.ConfigMapNameReference) string {
	return ""
}

func getFilenameFromSecretNameRef(ref configv1.SecretNameReference) string {
	return ""
}
