// Package generation converts the OIDC provider configuration from the
// cluster Authentication resource into the external OIDC authentication
// configuration consumed by oauth-apiserver.
//
// Consumers provide resolvers for referenced certificate-authority ConfigMaps
// and client Secrets. The package deliberately does not depend on Kubernetes
// clients, listers, namespaces, or feature-gate implementations, allowing both
// standalone OpenShift and hosted control planes to supply their own lookup
// mechanisms.
package generation
