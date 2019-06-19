package util

const (
	GlobalConfigName = "cluster"

	TargetName = "oauth-openshift" // this value must be "namespaced" to avoid using a route host that a customer may want

	OAuthBrowserClientName     = "openshift-browser-client"
	OAuthChallengingClientName = "openshift-challenging-client"
)
