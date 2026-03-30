package library

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
)

// CheckFeatureGatesOrSkip checks if any of the required feature gates are enabled.
// If none are enabled, the test is skipped.
func CheckFeatureGatesOrSkip(t testing.TB, ctx context.Context, configClient *configclient.Clientset, features ...configv1.FeatureGateName) {
	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	if len(featureGates.Status.FeatureGates) != 1 {
		// fail test if there are multiple feature gate versions (i.e. ongoing upgrade)
		t.Fatalf("multiple feature gate versions detected")
	}

	atLeastOneFeatureEnabled := false
	for _, feature := range features {
		for _, gate := range featureGates.Status.FeatureGates[0].Enabled {
			if gate.Name == feature {
				atLeastOneFeatureEnabled = true
				break
			}
		}

		if atLeastOneFeatureEnabled {
			break
		}
	}

	if !atLeastOneFeatureEnabled {
		t.Skipf("skipping as none of the feature gates in %v are enabled", features)
	}
}
