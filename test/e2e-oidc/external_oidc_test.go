package e2e_oidc

import (
	"context"
	"testing"
)

// This test function allows the e2e-oidc test to be run via standard `go test` command.
// It calls the shared test implementation which is also used by the Ginkgo/OTE framework.
//
// This situation is temporary until we verify the new e2e-oidc-ote CI job.
// Eventually all tests will be run only as part of the OTE framework.
func TestExternalOIDCWithKeycloak(t *testing.T) {
	testContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	testExternalOIDCWithKeycloak(testContext, t)
}
