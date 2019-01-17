package operator2

import configv1 "github.com/openshift/api/config/v1"

func createFileStringSource(filename string) configv1.StringSource {
	return configv1.StringSource{
		StringSourceSpec: configv1.StringSourceSpec{
			File: filename,
		},
	}
}
