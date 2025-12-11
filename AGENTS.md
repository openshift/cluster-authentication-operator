# AGENTS.md

OpenShift operator that manages OAuth Server and OAuth API Server for cluster authentication.

## What This Operator Does

This operator manages the authentication infrastructure for OpenShift clusters:

- **OAuth Server** (`openshift-authentication` namespace) - Handles user authentication via identity providers (HTPasswd, LDAP, OIDC, Request Header, etc.)
- **OAuth API Server** (`openshift-oauth-apiserver` namespace) - Manages OAuth API resources and client registrations
- **Controllers** - Each controller watches specific cluster resources and reconciles authentication state
- **Token Encryption** - Manages encryption of OAuth tokens at rest with key rotation support
- **Identity Provider Configuration** - Syncs IdP configs from `openshift-config` to the OAuth server

The operator runs in `openshift-authentication-operator` namespace and orchestrates both OAuth components.

**External OIDC Mode:** Recent development focuses on external OIDC support. When external OIDC is enabled (via `Authentication.config.openshift.io/cluster` spec), the operator disables the default OAuth stack and configures the cluster to use an external OIDC provider instead. See `pkg/controllers/externaloidc/` for implementation. Future feature development should be focused on external OIDC support, and the existing OAuth stack is considered feature complete.

## Commands

```bash
# Build and verify
make build
make verify
make verify-bindata

# Testing
make test-unit                          # Fast unit tests
make test-e2e                           # E2E tests (1h)
make run-e2e-test WHAT=TestCustomRoute  # Specific test

# NEVER run encryption tests in parallel
make test-e2e-encryption                # Serial only, 4h timeout

# Update embedded assets
make update-bindata                     # After modifying bindata/ YAML files
make verify-bindata                     # Verify bindata is current

# Dependencies
go get <module>@<version>
go mod tidy
make verify
```

## Tech Stack

- **Go** - Check `go.mod` for current version
- **Kubernetes client-go** - Check `go.mod` for current version
- **OpenShift library-go** - Controller factory, resourceapply, operatorhelpers
- **OpenShift api** - Authentication/OAuth CRDs
- **klog/v2** - Structured logging
- **Cobra** - CLI framework

## Always Do

- **Use informers and listers** - Never make direct API calls in controller sync loops
- **Run `make update-bindata`** after modifying any YAML in `bindata/oauth-openshift/` or `bindata/oauth-apiserver/`
- **Use `resourceapply` helpers** - `ApplyDeployment()`, `ApplyService()`, etc. from library-go
- **Return errors from sync()** to trigger automatic retry
- **Use table-driven tests** for unit tests
- **Log with klog** - Use structured logging with klog.V() levels
- **Reference files with line numbers** - Format: `pkg/controllers/deployment/controller.go:123`

## Ask First

- **Adding new controllers** - Must register in `pkg/operator/starter.go` and add RBAC to manifests
- **Changing RBAC permissions** - Update `manifests/` files
- **Modifying encryption logic** - Impacts security and requires encryption test validation
- **Changing operator namespaces** - Multiple namespaces involved (see below)
- **Adding new CRD dependencies** - Check vendoring and bindata requirements

## Never Do

- **Never commit secrets** or credentials to the repo
- **Never modify `vendor/`** directly - Use `go get` and `go mod tidy`
- **Never skip encryption tests** - They're serial and slow (4h) but critical
- **Never make direct API calls in controllers** - Always use informers/listers for performance
- **Never modify bindata/ without running `make update-bindata`**
- **Never run encryption tests in parallel** - They must run serially (`-p 1 -parallel 1`)
- **Never use generic "helpful assistant" code** - Follow OpenShift operator patterns

## Controller Pattern

All controllers follow the library-go factory pattern:

```go
import (
    "github.com/openshift/library-go/pkg/controller/factory"
    "github.com/openshift/library-go/pkg/operator/v1helpers"
)

func NewMyController(
    operatorClient v1helpers.OperatorClient,
    kubeInformers informers.SharedInformerFactory,
    recorder events.Recorder,
) factory.Controller {
    c := &myController{
        operatorClient: operatorClient,
        lister:        kubeInformers.Apps().V1().Deployments().Lister(),
    }

    return factory.New().
        WithInformers(kubeInformers.Apps().V1().Deployments().Informer()).
        WithSync(c.sync).
        ToController("MyController", recorder)
}

func (c *myController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
    // Use listers, never direct API calls
    deployment, err := c.lister.Deployments("namespace").Get("name")
    if err != nil {
        return err // Return error to trigger retry
    }

    // Use resourceapply for declarative updates
    _, _, err = resourceapply.ApplyDeployment(
        ctx,
        c.client,
        recorder,
        requiredDeployment,
    )
    return err
}
```

## Key File Locations

```
pkg/operator/starter.go              # Register new controllers here
pkg/controllers/<name>/              # Controller implementations
pkg/operator/configobservation/      # Config observers
pkg/operator/workload/               # OAuth API Server workload
bindata/oauth-openshift/             # OAuth server manifests (14 YAML files)
bindata/oauth-apiserver/             # OAuth API server manifests (10 YAML files)
manifests/                           # Operator RBAC and deployment
test/e2e/                           # E2E tests
test/library/                       # Shared test utilities
```

## Namespaces

- `openshift-authentication-operator` - This operator runs here
- `openshift-authentication` - OAuth server runs here
- `openshift-oauth-apiserver` - OAuth API server runs here
- `openshift-config` - User-provided configuration (secrets/configmaps for IdPs, TLS certs, CA bundles, etc.)
- `openshift-config-managed` - Operator-managed configuration

## Common Workflows

### Add a Controller

1. Create `pkg/controllers/<name>/<name>_controller.go`
2. Implement factory pattern with `sync()` method
3. Register in `pkg/operator/starter.go`
4. Add RBAC to `manifests/` if needed
5. Add unit tests in `*_test.go`

### Modify Embedded Manifests

```bash
# Edit YAML
vim bindata/oauth-openshift/deployment.yaml

# Update embedded Go code
make update-bindata

# Verify
make verify-bindata
```

### Add a Test

```go
// Unit test - co-located with source
func TestMyController_Sync(t *testing.T) {
    tests := []struct {
        name    string
        setup   func(*fakeClient)
        wantErr bool
    }{
        // Table-driven test cases
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Security Notes

- This operator manages cluster authentication - security is critical
- OAuth tokens encrypted at rest with key rotation support
- Never log secrets or credentials
- Validate all external IdP configurations
