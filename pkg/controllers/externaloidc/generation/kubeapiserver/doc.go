// kubeapiserver serves the purpose of generating the
// AuthenticationConfiguration types for configuring the
// Kubernetes API Server with a direct OIDC provider token authenticator.
//
// TODO: Remove this package once the ExternalOIDCExternalClaimsSourcing feature gate
// has been promoted to the default feature set as the Kubernetes API server
// will no longer be the thing getting configured and thus we will not need
// this generation behavior.
// Tracking Jira ticket: https://redhat.atlassian.net/browse/CNTRLPLANE-3454
package kubeapiserver
