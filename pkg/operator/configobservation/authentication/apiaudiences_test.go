package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/operator/configobservation"
)

func TestObservedConfig(t *testing.T) {
	for _, tc := range []struct {
		name              string
		issuer            string
		authMissing       bool
		existingIssuer    string
		expectedAudiences string
		expectedChange    bool
	}{
		{
			name:              "no issuer, no previous issuer",
			existingIssuer:    "",
			issuer:            "",
			expectedAudiences: "https://kubernetes.default.svc",
			expectedChange:    true,
		},
		{
			name:              "no issuer, default already observed",
			existingIssuer:    "https://kubernetes.default.svc",
			issuer:            "",
			expectedAudiences: "https://kubernetes.default.svc",
		},
		{
			name:              "no issuer, previous issuer set",
			existingIssuer:    "https://example.com",
			issuer:            "",
			expectedAudiences: "https://kubernetes.default.svc",
			expectedChange:    true,
		},
		{
			name:              "issuer set, no previous issuer",
			existingIssuer:    "",
			issuer:            "https://example.com",
			expectedAudiences: "https://example.com",
			expectedChange:    true,
		},
		{
			name:              "issuer set, previous issuer same",
			existingIssuer:    "https://example.com",
			issuer:            "https://example.com",
			expectedAudiences: "https://example.com",
		},
		{
			name:              "issuer set, previous issuer different",
			existingIssuer:    "https://example.com",
			issuer:            "https://example2.com",
			expectedAudiences: "https://example2.com",
			expectedChange:    true,
		},
		{
			name:              "auth missing",
			existingIssuer:    "https://example2.com",
			issuer:            "",
			authMissing:       true,
			expectedChange:    true,
			expectedAudiences: "https://kubernetes.default.svc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if !tc.authMissing {
				authConfig := authConfigForIssuer(tc.issuer)

				err := indexer.Add(authConfig)
				require.NoError(t, err)
			}

			testRecorder := events.NewInMemoryRecorder("APIAudiencesTest")
			listers := configobservation.Listers{
				AuthConfigLister_: configlistersv1.NewAuthenticationLister(indexer),
			}

			newConfig, errs := ObserveAPIAudiences(
				listers,
				testRecorder,
				apiConfigForIssuer(tc.existingIssuer),
			)

			require.Len(t, errs, 0)

			expectedConfig := apiConfigForIssuer(tc.expectedAudiences)

			require.Equal(t, expectedConfig, newConfig)
			require.True(t, tc.expectedChange == (len(testRecorder.Events()) > 0))
		})
	}
}

func authConfigForIssuer(issuer string) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.AuthenticationSpec{
			ServiceAccountIssuer: issuer,
		},
	}
}

func apiConfigForIssuer(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"apiServerArguments": map[string]interface{}{
			"api-audiences": []interface{}{
				issuer,
			},
		},
	}
}
