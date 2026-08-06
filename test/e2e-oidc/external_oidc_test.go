package e2e_oidc

import (
	"testing"
)

// This test calls the shared test function which
// can be called from both standard Go tests and Ginkgo tests.
//
// This situation is temporary until we verify the new e2e-openshift-cluster-authentication-oidc-ote job.
// Eventually all tests will be run only as part of the OTE framework.
func TestExternalOIDCWithKeycloak(tt *testing.T) {
	testExternalOIDCWithKeycloak(tt.Context(), tt)
}
