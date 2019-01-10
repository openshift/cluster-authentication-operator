package operator2

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	kubejson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

func TestConvertProviderConfigToOsinBytes(t *testing.T) {
	serializer := kubejson.NewYAMLSerializer(kubejson.DefaultMetaFactory, scheme, scheme)

	var BasicAuth osinv1.BasicAuthPasswordIdentityProvider

	providerConfig := configv1.IdentityProviderConfig{
		Type: configv1.IdentityProviderTypeBasicAuth,
		BasicAuth: &configv1.BasicAuthIdentityProvider{
			OAuthRemoteConnectionInfo: configv1.OAuthRemoteConnectionInfo{
				URL:           "https://vseckonfunguje.com/auth",
				CA:            configv1.ConfigMapNameReference{Name: "configmap-somewhere"},
				TLSClientCert: configv1.SecretNameReference{Name: "secret-somewhere"},
				TLSClientKey:  configv1.SecretNameReference{Name: "secret-somewhereelse"},
			},
		},
	}
	providerConfigConverted := osinv1.BasicAuthPasswordIdentityProvider{
		RemoteConnectionInfo: configv1.RemoteConnectionInfo{
			URL: providerConfig.BasicAuth.URL,
			CA:  getFilenameFromConfigMapNameRef(providerConfig.BasicAuth.CA),
			CertInfo: configv1.CertInfo{
				CertFile: getFilenameFromSecretNameRef(providerConfig.BasicAuth.TLSClientCert),
				KeyFile:  getFilenameFromSecretNameRef(providerConfig.BasicAuth.TLSClientKey),
			},
		},
	}
	out, err := convertProviderConfigToOsinBytes(&providerConfig)
	if err != nil {
		t.Errorf("got unexpected error: '%s'", err)
	}

	_, _, err = serializer.Decode(out, nil, &BasicAuth)
	if err != nil {
		t.Errorf("could not deserialize the conversion output data: '%s'", err)
	}

	if BasicAuth != providerConfigConverted {
		t.Errorf("expected '%v', got '%#v'", "", BasicAuth)
	}
}
